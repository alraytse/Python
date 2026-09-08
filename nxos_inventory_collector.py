#!/usr/bin/env python3
"""Read-only NX-OS IP/interface and firewall inventory collector.

The script collects:
  * Existing low-MAC/low-ARP VLAN/STP evidence.
  * All configured NX-OS interfaces, including Loopback, Tunnel, VLAN/SVI,
    Port-channel, subinterfaces, NVE, management, and other logical interfaces.
  * Best-effort NX-OS NAT output when the platform supports the commands.
  * Firewall interfaces, NAT/PAT evidence, and VPN/tunnel evidence into a
    separate firewall CSV.

No configuration is changed. Firewall command coverage is platform-dependent;
unsupported commands are recorded as unavailable rather than treated as data.

When --switch-hosts or --firewall-hosts are omitted, the script prompts for
comma-delimited devices. It also prompts for a User ID and password. Collection
runs concurrently with 15 workers by default; use --workers to override it.
"""

import argparse
import csv
import getpass
import io
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.request import Request, urlopen

try:
    from netmiko import ConnectHandler
except ImportError:
    ConnectHandler = None

STP_CSV_FILE = "stp_vlan_report.csv"
INTERFACE_CSV_FILE = "interface_ip_report.csv"
NAT_RULE_CSV_FILE = "nat_rules_report.csv"
FIREWALL_CSV_FILE = "firewall_inventory.csv"

MAC_OID_BASE = "1.3.6.1.2.1.17.4.3.1.1"
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
DEFAULT_MAX_MAC_COUNT = 2
DEFAULT_MAX_ARP_COUNT = 2
DEFAULT_WORKERS = 15
MAX_WORKERS = 15

MAC_PATTERN = (
    r"[0-9a-fA-F]{4}(?:[.:-][0-9a-fA-F]{4}){2}|"
    r"[0-9a-fA-F]{12}"
)
IP_PATTERN = (
    r"(?:(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|"
    r"[0-9a-fA-F:]+:[0-9a-fA-F:]+(?:/\d{1,3})?)"
)

UNSUPPORTED_MARKERS = (
    "% Invalid",
    "% Incomplete",
    "% Ambiguous",
    "Invalid input",
    "Unknown command",
    "Command fail",
    "Command not found",
    "No such command",
    "syntax error",
)


def connect_handler(**kwargs):
    if ConnectHandler is None:
        raise RuntimeError(
            "Live collection requires Netmiko. Install it with: pip install netmiko"
        )
    return ConnectHandler(**kwargs)


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------


def split_hosts(value):
    return [item.strip() for item in value.split(",") if item.strip()]


def safe_send_command(connection, command, read_timeout=30):
    try:
        output = connection.send_command(command, read_timeout=read_timeout)
        if not output or any(marker.lower() in output.lower() for marker in UNSUPPORTED_MARKERS):
            return ""
        return output
    except Exception:
        return ""


def get_hostname(connection):
    prompt = connection.find_prompt()
    return prompt.replace("#", "").replace(">", "").strip()


def unique_join(values):
    return "; ".join(dict.fromkeys(value for value in values if value))


def extract_ips(text):
    values = []
    for value in re.findall(IP_PATTERN, text):
        if value not in values:
            values.append(value)
    return values


def write_rows(rows, csv_file, fields):
    path = Path(csv_file)
    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Existing OUI/MAC/STP collection
# ---------------------------------------------------------------------------


def normalize_mac(mac):
    hex_digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hex_digits) != 12:
        raise ValueError(f"Invalid MAC address: {mac}")
    return [int(hex_digits[index:index + 2], 16) for index in range(0, 12, 2)]


def format_mac(mac, output_format="cisco"):
    octets = normalize_mac(mac)
    value = "".join(f"{octet:02x}" for octet in octets)

    if output_format == "colon":
        return ":".join(value[index:index + 2] for index in range(0, 12, 2))
    if output_format == "hyphen":
        return "-".join(value[index:index + 2] for index in range(0, 12, 2))
    return ".".join(value[index:index + 4] for index in range(0, 12, 4))


def mac_to_oid(mac, base_oid=MAC_OID_BASE):
    mac_octets = normalize_mac(mac)
    base_parts = [int(part) for part in base_oid.strip(".").split(".")]
    return ".".join(str(value) for value in base_parts + mac_octets)


def parse_vlans(output):
    vlan_map = {}
    for line in output.splitlines():
        match = re.match(r"^(\d+)\s+(\S+)", line.strip())
        if match:
            vlan_map[match.group(1)] = {
                "vlan": match.group(1),
                "name": match.group(2),
            }
    return list(vlan_map.values())


def parse_mac_table(output):
    entries = []
    mac_pattern = (
        r"^\s*\*?\s*(\d+)\s+"
        r"([0-9a-fA-F]{4}(?:[.:-][0-9a-fA-F]{4}){2}|"
        r"[0-9a-fA-F]{12})\b"
    )

    for line in output.splitlines():
        match = re.match(mac_pattern, line)
        is_dynamic = re.search(r"\bdynamic\b", line, re.IGNORECASE)
        port_match = re.search(
            r"\b((?:Eth(?:ernet)?|Po(?:rt-channel)?|port-channel|"
            r"sup-eth|mgmt)\S*)\s*$",
            line,
            re.IGNORECASE,
        )
        if match and is_dynamic:
            entries.append({
                "vlan": match.group(1),
                "mac": format_mac(match.group(2)),
                "port": port_match.group(1) if port_match else "",
            })
    return entries


def is_port_channel(port):
    return bool(re.match(r"^(?:po|port-channel)\S*$", port.strip(), re.IGNORECASE))


def parse_arp_table(output):
    vlan_pattern = r"\b[Vv]lan(\d+)\b"
    arp_entries = {}

    for line in output.splitlines():
        mac_match = re.search(MAC_PATTERN, line)
        vlan_match = re.search(vlan_pattern, line)
        if mac_match and vlan_match:
            vlan = vlan_match.group(1)
            arp_entries.setdefault(vlan, set()).add(format_mac(mac_match.group(0)))
    return arp_entries


def get_arp_table(connection):
    try:
        output = connection.send_command("show ip arp", read_timeout=30)
        return parse_arp_table(output), True
    except Exception as error:
        print(f"ARP lookup failed: {error}")
        return {}, False


def get_arp_count(arp_entries, vlan):
    return len(arp_entries.get(str(vlan), set()))


def check_mac_arp(mac_info, vlan, arp_entries, arp_available):
    macs = [mac.strip() for mac in mac_info["MAC_Address"].split(";") if mac.strip()]
    if not arp_available:
        return "ARP_UNAVAILABLE", ""
    if not macs:
        return "NO_MACS", ""

    vlan_arp_macs = arp_entries.get(str(vlan), set())
    missing_macs = [mac for mac in macs if mac not in vlan_arp_macs]
    if missing_macs:
        return "MISSING_ARP", "; ".join(missing_macs)
    return "PASS", ""


def normalize_assignment(value):
    value = re.sub(r"[^0-9a-fA-F]", "", value)
    return value[:6].upper() if len(value) >= 6 else ""


def read_oui_csv(csv_text):
    reader = csv.DictReader(io.StringIO(csv_text))
    if not reader.fieldnames:
        raise ValueError("The OUI file does not contain a CSV header.")

    assignment_field = next(
        (field for field in reader.fieldnames if field.strip().lower() == "assignment"),
        None,
    )
    organization_field = next(
        (
            field
            for field in reader.fieldnames
            if field.strip().lower() in {"organization name", "organization"}
        ),
        None,
    )
    if not assignment_field or not organization_field:
        raise ValueError("The OUI CSV must contain Assignment and Organization Name columns.")

    organizations = {}
    for row in reader:
        assignment = normalize_assignment(row.get(assignment_field, ""))
        organization = row.get(organization_field, "").strip()
        if assignment and organization:
            organizations[assignment] = organization
    return organizations


def load_oui_registry(oui_file=None, offline=False):
    if oui_file:
        return read_oui_csv(Path(oui_file).read_text(encoding="utf-8"))
    if offline:
        return {}

    request = Request(IEEE_OUI_URL, headers={"User-Agent": "network-ip-collection/1.0"})
    with urlopen(request, timeout=20) as response:
        return read_oui_csv(response.read().decode("utf-8-sig"))


def decode_mac(mac, base_oid, oui_registry):
    octets = normalize_mac(mac)
    oui = "".join(f"{octet:02X}" for octet in octets[:3])
    formatted_oui = f"{oui[:2]}-{oui[2:4]}-{oui[4:6]}"
    oid = mac_to_oid(mac, base_oid)

    if octets[0] & 0x01:
        company = "Multicast address"
    elif octets[0] & 0x02:
        company = "Locally administered/randomized MAC"
    else:
        company = oui_registry.get(oui, "Not found in IEEE OUI registry")
    return formatted_oui, oid, company


def get_mac_info(connection, vlan, base_oid, oui_registry):
    try:
        output = connection.send_command("show mac address-table", read_timeout=30)
        entries = [
            entry
            for entry in parse_mac_table(output)
            if entry["vlan"] == str(vlan) and not is_port_channel(entry["port"])
        ]

        mac_addresses = []
        mac_companies = []
        mac_ports = []
        for entry in entries:
            mac = entry["mac"]
            _, _, company = decode_mac(mac, base_oid, oui_registry)
            mac_addresses.append(mac)
            mac_companies.append(company)
            if entry["port"]:
                mac_ports.append(entry["port"])

        return {
            "MAC_Count": str(len(mac_addresses)),
            "MAC_Address": "; ".join(mac_addresses),
            "MAC_Company": "; ".join(mac_companies),
            "MAC_Port": "; ".join(dict.fromkeys(mac_ports)),
        }
    except Exception as error:
        print(f"MAC lookup failed for VLAN {vlan}: {error}")
        return {"MAC_Count": "0", "MAC_Address": "", "MAC_Company": "", "MAC_Port": ""}


def parse_interface_rate(output, direction):
    pattern = re.compile(
        rf"(?:5 minute|30 seconds)\s+{direction}put rate\s+([0-9,]+)\s+bits/sec",
        re.IGNORECASE,
    )
    rates = [int(match.group(1).replace(",", "")) for match in pattern.finditer(output)]
    return max(rates, default=None)


def check_port_traffic(connection, port_list):
    ports = [port.strip() for port in port_list.split(";") if port.strip()]
    if not ports:
        return "NO_ACCESS_PORTS", "", ""

    checked_ports = []
    statistics = []
    traffic_detected = False
    successful_checks = 0

    for port in dict.fromkeys(ports):
        try:
            output = connection.send_command(f"show interface {port}", read_timeout=30)
            input_rate = parse_interface_rate(output, "in")
            output_rate = parse_interface_rate(output, "out")
            if input_rate is None and output_rate is None:
                continue

            successful_checks += 1
            checked_ports.append(port)
            statistics.append(
                f"{port}: IN {input_rate if input_rate is not None else 'N/A'} "
                f"bps / OUT {output_rate if output_rate is not None else 'N/A'} bps"
            )
            if (input_rate or 0) > 0 or (output_rate or 0) > 0:
                traffic_detected = True
        except Exception:
            continue

    if traffic_detected:
        status = "TRAFFIC_DETECTED"
    elif successful_checks:
        status = "NO_TRAFFIC"
    else:
        status = "TRAFFIC_UNAVAILABLE"
    return status, "; ".join(checked_ports), "; ".join(statistics)


def check_root(connection, vlan):
    try:
        output = connection.send_command(f"show spanning-tree vlan {vlan}", read_timeout=30)
        return "This bridge is the root" in output
    except Exception:
        return False


def get_svi_info(connection, vlan, base_oid, oui_registry):
    description = ""
    ip_address = ""
    svi_mac = ""
    svi_company = ""

    try:
        output = connection.send_command(f"show run interface vlan {vlan}", read_timeout=30)
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("description "):
                description = line.replace("description ", "", 1)
            elif line.startswith("ip address "):
                ip_address = line.replace("ip address ", "", 1)
    except Exception:
        pass

    try:
        output = connection.send_command(f"show interface vlan {vlan}", read_timeout=30)
        match = re.search(r"\baddress is\s+(" + MAC_PATTERN + r")\b", output, re.IGNORECASE)
        if match:
            svi_mac = format_mac(match.group(1))
            _, _, svi_company = decode_mac(svi_mac, base_oid, oui_registry)
    except Exception:
        pass

    return description, ip_address, svi_mac, svi_company


def process_stp_switch(connection, hostname, base_oid, oui_registry, max_mac_count, max_arp_count):
    results = []
    vlan_output = connection.send_command("show vlan brief", read_timeout=30)
    vlans = parse_vlans(vlan_output)
    arp_entries, arp_available = get_arp_table(connection)
    print(f"{hostname}: Found {len(vlans)} VLANs")

    for vlan_info in vlans:
        vlan_id = vlan_info["vlan"]
        mac_info = get_mac_info(connection, vlan_id, base_oid, oui_registry)
        mac_count = int(mac_info["MAC_Count"])
        arp_count = get_arp_count(arp_entries, vlan_id)

        if arp_available:
            if mac_count > max_mac_count or arp_count > max_arp_count:
                continue
        elif mac_count > max_mac_count:
            continue

        traffic_check = "NOT_CHECKED"
        traffic_ports = ""
        traffic_statistics = ""
        if mac_count >= 1:
            traffic_check, traffic_ports, traffic_statistics = check_port_traffic(
                connection, mac_info["MAC_Port"]
            )

        arp_check, arp_missing_macs = check_mac_arp(
            mac_info, vlan_id, arp_entries, arp_available
        )
        svi_description, svi_ip, svi_mac, svi_company = get_svi_info(
            connection, vlan_id, base_oid, oui_registry
        )
        is_root = check_root(connection, vlan_id)

        results.append({
            "Device": hostname,
            "VLAN": vlan_id,
            "VLAN_Name": vlan_info["name"],
            "SVI_IP": svi_ip,
            "SVI_MAC": svi_mac,
            "SVI_MAC_Company": svi_company,
            "SVI_Description": svi_description,
            "MAC_Count": mac_info["MAC_Count"],
            "ARP_Count": str(arp_count),
            "Traffic_Check": traffic_check,
            "Traffic_Ports": traffic_ports,
            "Traffic_Statistics": traffic_statistics,
            "MAC_Address": mac_info["MAC_Address"],
            "MAC_Company": mac_info["MAC_Company"],
            "ARP_Check": arp_check,
            "ARP_Missing_MACs": arp_missing_macs,
            "Root_Bridge": "YES" if is_root else "NO",
            "Shutdown_Recommendation": (
                "YES" if mac_count == 0 and arp_count == 0 else "NO"
            ),
        })
    return results


STP_FIELDS = [
    "Device", "VLAN", "VLAN_Name", "SVI_IP", "SVI_MAC", "SVI_MAC_Company",
    "SVI_Description", "MAC_Count", "ARP_Count", "Traffic_Check", "Traffic_Ports",
    "Traffic_Statistics", "MAC_Address", "MAC_Company", "ARP_Check",
    "ARP_Missing_MACs", "Root_Bridge", "Shutdown_Recommendation",
]


def deduplicate_results(results):
    unique_results = {}
    for row in results:
        vlan_id = str(int(row["VLAN"]))
        row["VLAN"] = vlan_id
        unique_results.setdefault((row["Device"], vlan_id), row)
    return list(unique_results.values())


# ---------------------------------------------------------------------------
# NX-OS interface/IP inventory
# ---------------------------------------------------------------------------


def classify_interface(interface):
    name = interface.lower()
    if name.startswith(("loopback", "lo")):
        return "Loopback"
    if name.startswith(("tunnel", "tun", "vti", "svti")):
        return "Tunnel"
    if name.startswith(("vlan", "svi")):
        return "SVI/VLAN"
    if name.startswith(("port-channel", "po")):
        return "Port-channel"
    if name.startswith(("nve", "vxlan")):
        return "NVE/VXLAN"
    if name.startswith(("mgmt", "management")):
        return "Management"
    if name.startswith(("null", "discard")):
        return "Null/Discard"
    if name.startswith(("bdi", "bvi", "irb", "bridge", "ve")):
        return "Bridge/IRB"
    if "." in name:
        return "Subinterface"
    if name.startswith(("ethernet", "eth", "e1/", "e")):
        return "Physical Ethernet"
    return "Other logical/interface"


def parse_nxos_interface_config(output, device):
    rows = []
    current = None

    def save_current():
        if current is None:
            return
        rows.append({
            "Device": device,
            "Interface": current["Interface"],
            "Interface_Type": classify_interface(current["Interface"]),
            "Description": current["Description"],
            "VRF": current["VRF"],
            "IPv4_Addresses": unique_join(current["IPv4_Addresses"]),
            "IPv6_Addresses": unique_join(current["IPv6_Addresses"]),
            "IP_Unnumbered": current["IP_Unnumbered"],
            "Tunnel_Source": current["Tunnel_Source"],
            "Tunnel_Destination": current["Tunnel_Destination"],
            "Tunnel_Mode": current["Tunnel_Mode"],
            "Admin_State": current["Admin_State"],
            "Operational_IP": "",
            "Line_Protocol": "",
        })

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        interface_match = re.match(r"^interface\s+(\S+)", line, re.IGNORECASE)
        if interface_match:
            save_current()
            current = {
                "Interface": interface_match.group(1),
                "Description": "",
                "VRF": "default",
                "IPv4_Addresses": [],
                "IPv6_Addresses": [],
                "IP_Unnumbered": "",
                "Tunnel_Source": "",
                "Tunnel_Destination": "",
                "Tunnel_Mode": "",
                "Admin_State": "up",
            }
            continue

        if current is None:
            continue
        stripped = line.strip()
        if not line.startswith((" ", "\t")) and stripped:
            save_current()
            current = None
            continue

        if stripped.startswith("description "):
            current["Description"] = stripped.replace("description ", "", 1)
        elif stripped.startswith("vrf member "):
            current["VRF"] = stripped.replace("vrf member ", "", 1)
        elif stripped == "shutdown":
            current["Admin_State"] = "shutdown"
        elif stripped.startswith("ip address ") and not stripped.startswith("ip address virtual"):
            current["IPv4_Addresses"].append(stripped.replace("ip address ", "", 1))
        elif stripped.startswith("ipv6 address "):
            current["IPv6_Addresses"].append(stripped.replace("ipv6 address ", "", 1))
        elif stripped.startswith("ip unnumbered "):
            current["IP_Unnumbered"] = stripped.replace("ip unnumbered ", "", 1)
        elif stripped.startswith("tunnel source "):
            current["Tunnel_Source"] = stripped.replace("tunnel source ", "", 1)
        elif stripped.startswith("tunnel destination "):
            current["Tunnel_Destination"] = stripped.replace("tunnel destination ", "", 1)
        elif stripped.startswith("tunnel mode "):
            current["Tunnel_Mode"] = stripped.replace("tunnel mode ", "", 1)

    save_current()
    return rows


def parse_nxos_ip_brief(output):
    states = {}
    valid_state = r"(?:up|down|admin-down|administratively\s+down|unknown)"
    pattern = re.compile(
        rf"^\s*(\S+)\s+({valid_state})\s+({valid_state})\s+(\S+)\s*$",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        ip_value, status, protocol, interface = match.groups()
        if interface.lower() in {"interface", "protocol"}:
            continue
        states[interface] = {
            "Operational_IP": ip_value,
            "Admin_State": status,
            "Line_Protocol": protocol,
        }
    return states


def collect_nxos_interfaces(connection, device):
    running_config = safe_send_command(connection, "show running-config", read_timeout=60)
    rows = parse_nxos_interface_config(running_config, device) if running_config else []

    brief_output = safe_send_command(
        connection, "show ip interface brief vrf all", read_timeout=30
    )
    states = parse_nxos_ip_brief(brief_output) if brief_output else {}
    by_interface = {row["Interface"].lower(): row for row in rows}

    for interface, state in states.items():
        row = by_interface.get(interface.lower())
        if row is None:
            row = {
                "Device": device,
                "Interface": interface,
                "Interface_Type": classify_interface(interface),
                "Description": "",
                "VRF": "",
                "IPv4_Addresses": "",
                "IPv6_Addresses": "",
                "IP_Unnumbered": "",
                "Tunnel_Source": "",
                "Tunnel_Destination": "",
                "Tunnel_Mode": "",
                "Admin_State": "",
                "Operational_IP": "",
                "Line_Protocol": "",
            }
            rows.append(row)
            by_interface[interface.lower()] = row
        row.update(state)

    return rows


# ---------------------------------------------------------------------------
# Configured NAT/PAT rule collection
# ---------------------------------------------------------------------------


NAT_RULE_FIELDS = [
    "Device",
    "Platform",
    "Rule_Type",
    "Original_Source",
    "Translated_Source",
    "Original_Destination",
    "Translated_Destination",
    "Protocol",
    "Original_Port",
    "Translated_Port",
    "Interface_or_ACL",
    "Command",
    "Details",
]

NAT_CONFIG_COMMAND_ECHO_RE = re.compile(
    r"^(?:show\s+(?:running-config|configuration|config)|get\s+|diagnose\s+)",
    re.IGNORECASE,
)


def nat_rule_row(
    device,
    platform,
    command,
    details,
    rule_type="NAT",
    original_source="",
    translated_source="",
    original_destination="",
    translated_destination="",
    protocol="",
    original_port="",
    translated_port="",
    interface_or_acl="",
):
    return {
        "Device": device,
        "Platform": platform,
        "Rule_Type": rule_type,
        "Original_Source": original_source,
        "Translated_Source": translated_source,
        "Original_Destination": original_destination,
        "Translated_Destination": translated_destination,
        "Protocol": protocol,
        "Original_Port": original_port,
        "Translated_Port": translated_port,
        "Interface_or_ACL": interface_or_acl,
        "Command": command,
        "Details": details,
    }


def _first_non_ip_token(value):
    value = value.strip().strip(",")
    if value.lower() in {"host", "object", "network", "service"}:
        return ""
    return value


def parse_configured_nat_line(line, context_ip="", context_object=""):
    """Extract configured NAT rule fields from common firewall/switch syntax."""
    lower = line.lower()
    ips = extract_ips(line)
    protocol_match = re.search(r"\b(tcp|udp|icmp)\b", line, re.IGNORECASE)
    protocol = protocol_match.group(1).lower() if protocol_match else ""

    original_source = ""
    translated_source = ""
    original_destination = ""
    translated_destination = ""
    original_port = ""
    translated_port = ""

    # Cisco IOS/NX-OS:
    # ip nat inside source static [tcp|udp] <inside> [port] <global> [port]
    ios_source_static = re.search(
        r"\bsource\s+static\b", line, re.IGNORECASE
    )
    if ios_source_static and len(ips) >= 2:
        original_source = ips[0]
        translated_source = ips[1]
        ios_protocol = re.search(
            r"\bsource\s+static\s+(tcp|udp)\b", line, re.IGNORECASE
        )
        if ios_protocol:
            protocol = ios_protocol.group(1).lower()
            port_pair = re.search(
                r"\b(?:tcp|udp)\s+\S+\s+(\d{1,5})\s+\S+\s+(\d{1,5})\b",
                line,
                re.IGNORECASE,
            )
            if port_pair:
                original_port = port_pair.group(1)
                translated_port = port_pair.group(2)

    # Cisco ASA-style direct NAT:
    # nat (inside,outside) static <global> <local> service tcp <port> <port>
    asa_static_match = re.search(
        r"\bnat\s*\(([^)]+)\)\s+static\s+",
        line,
        re.IGNORECASE,
    )
    if asa_static_match and len(ips) >= 2:
        original_source = ips[0]
        translated_source = ips[1]
        service_match = re.search(
            r"\bservice\s+(tcp|udp)\s+(\d{1,5})\s+(\d{1,5})\b",
            line,
            re.IGNORECASE,
        )
        if service_match:
            protocol = service_match.group(1).lower()
            original_port = service_match.group(2)
            translated_port = service_match.group(3)

    service_match = re.search(
        r"\bservice\s+(tcp|udp)\s+(\d{1,5})\s+(\d{1,5})\b",
        line,
        re.IGNORECASE,
    )
    if service_match:
        protocol = service_match.group(1).lower()
        original_port = service_match.group(2)
        translated_port = service_match.group(3)

    # ASA object NAT often places the source address on the preceding object
    # lines and only the translated address on the nat line.
    if "nat (" in lower and "static" in lower and len(ips) == 1 and context_ip:
        original_source = context_ip
        translated_source = ips[0]

    # Source/destination NAT statements using ACLs, objects, any, or interfaces.
    source_list_match = re.search(r"\bsource\s+list\s+(\S+)", line, re.IGNORECASE)
    source_match = re.search(
        r"\bsource\s+(?:static|dynamic)?\s*([^\s]+)", line, re.IGNORECASE
    )
    destination_match = re.search(
        r"\bdestination\s+(?:static|dynamic)?\s*([^\s]+)", line, re.IGNORECASE
    )
    if source_list_match and not original_source:
        original_source = source_list_match.group(1).rstrip(",")
    elif source_match and not original_source:
        candidate = source_match.group(1).rstrip(",")
        if candidate.lower() not in {"list", "interface"}:
            original_source = candidate
    if destination_match:
        original_destination = destination_match.group(1).rstrip(",")

    if len(ips) >= 2 and not original_source:
        original_source, translated_source = ips[0], ips[1]
    elif len(ips) == 1 and not translated_source:
        translated_source = ips[0]

    if context_ip and not original_source and "object" in lower:
        original_source = context_ip
    if "any" in lower and not original_destination:
        original_destination = "any"

    interface_match = re.search(r"\binterface\s+(\S+)", line, re.IGNORECASE)
    acl_match = re.search(r"\b(?:access-list|access\s+list|list)\s+(\S+)", line, re.IGNORECASE)
    scope = []
    if context_object:
        scope.append(f"Object:{context_object}")
    if acl_match:
        scope.append(f"ACL:{acl_match.group(1).rstrip(',')}")
    if interface_match:
        interface_name = interface_match.group(1).rstrip(",")
        scope.append(f"Interface:{interface_name}")
        if not translated_source:
            translated_source = interface_name
    if asa_static_match:
        scope.append(f"Zone:{asa_static_match.group(1)}")

    if any(term in lower for term in ("overload", "dynamic", "masquerade", "source-nat", "source nat")):
        rule_type = "PAT"
    elif "static" in lower or "vip" in lower or "destination-nat" in lower:
        rule_type = "STATIC_NAT"
    else:
        rule_type = "NAT"

    return nat_rule_row(
        device="",
        platform="",
        command="",
        details=line,
        rule_type=rule_type,
        original_source=original_source,
        translated_source=translated_source,
        original_destination=original_destination,
        translated_destination=translated_destination,
        protocol=protocol,
        original_port=original_port,
        translated_port=translated_port,
        interface_or_acl="; ".join(scope),
    )


def is_configured_nat_line(line):
    lower = line.lower()
    if not line or NAT_CONFIG_COMMAND_ECHO_RE.match(line):
        return False
    return any(
        term in lower
        for term in (
            "ip nat ",
            "nat (",
            " nat ",
            "source-nat",
            "destination-nat",
            "source nat",
            "destination nat",
            "set nat",
            "set source",
            "set destination",
            "source-translation",
            "destination-translation",
            "translated-address",
            "translated-port",
            "nat-policy",
            "firewall vip",
            "firewall ippool",
            "virtual-ip",
            "ippool",
        )
    )


def parse_configured_nat_output(output, device, platform, command):
    rows = []
    seen = set()
    context_ip = ""
    context_object = ""

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or NAT_CONFIG_COMMAND_ECHO_RE.match(line):
            continue

        object_match = re.match(r"object\s+network\s+(\S+)", line, re.IGNORECASE)
        if object_match:
            context_object = object_match.group(1)
            context_ip = ""
            continue

        host_match = re.match(r"host\s+(\S+)", line, re.IGNORECASE)
        if host_match:
            host_ips = extract_ips(host_match.group(1))
            context_ip = host_ips[0] if host_ips else ""
            continue

        if not is_configured_nat_line(line):
            continue

        row = parse_configured_nat_line(line, context_ip, context_object)
        row.update({"Device": device, "Platform": platform, "Command": command})
        key = (row["Device"], row["Platform"], row["Details"])
        if key not in seen:
            rows.append(row)
            seen.add(key)
    return rows


def collect_nxos_nat_rules(connection, device):
    """Collect configured NX-OS NAT/PAT rules, not active translations."""
    commands = (
        "show running-config | include ip nat",
        "show running-config | section ip nat",
        "show running-config | include ^nat",
    )
    rows = []
    for command in commands:
        output = safe_send_command(connection, command, read_timeout=60)
        if output:
            rows.extend(parse_configured_nat_output(output, device, "cisco_nxos", command))
    return _dedupe_nat_rules(rows)


def _dedupe_nat_rules(rows):
    unique = {}
    for row in rows:
        key = (row["Device"], row["Platform"], row["Details"])
        unique.setdefault(key, row)
    return list(unique.values())


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Concurrent switch collection
# ---------------------------------------------------------------------------


def collect_switch(host, username, password, args, oui_registry):
    connection = None
    try:
        print(f"\nConnecting to switch {host}...")
        connection = connect_handler(
            device_type="cisco_nxos",
            host=host,
            username=username,
            password=password,
            fast_cli=False,
        )
        hostname = get_hostname(connection) or host
        stp_results = process_stp_switch(
            connection,
            hostname,
            args.mac_oid_base,
            oui_registry,
            args.max_mac_count,
            args.max_arp_count,
        )
        interface_results = collect_nxos_interfaces(connection, hostname)
        nat_rule_results = collect_nxos_nat_rules(connection, hostname)
        return hostname, stp_results, interface_results, nat_rule_results
    except Exception as error:
        print(f"Failed to collect switch {host}: {error}")
        return host, [], [], []
    finally:
        if connection:
            connection.disconnect()


def collect_switches(hosts, username, password, args, oui_registry):
    results_by_host = {}
    worker_count = max(1, min(args.workers, MAX_WORKERS, len(hosts)))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(collect_switch, host, username, password, args, oui_registry): host
            for host in hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                results_by_host[host] = future.result()
            except Exception as error:
                print(f"Failed to collect switch {host}: {error}")
                results_by_host[host] = (host, [], [], [])

    ordered = [results_by_host[host] for host in hosts]
    stp_results = [row for result in ordered for row in result[1]]
    interface_results = [row for result in ordered for row in result[2]]
    nat_rule_results = [row for result in ordered for row in result[3]]
    return stp_results, interface_results, nat_rule_results


# ---------------------------------------------------------------------------
# Firewall collector
# ---------------------------------------------------------------------------


def firewall_profile(platform):
    profiles = {
        "cisco_asa": {
            "device_type": "cisco_asa",
            "interface": ["show interface ip brief", "show running-config interface"],
            "nat_config": [
                "show running-config nat",
                "show running-config object network",
                "show running-config object service",
                "show running-config global",
            ],
            "tunnel": [
                "show vpn-sessiondb l2l",
                "show crypto ipsec sa",
                "show crypto ikev2 sa",
                "show running-config crypto map",
                "show running-config tunnel-group",
            ],
        },
        "cisco_ftd": {
            "device_type": "cisco_asa",
            "interface": ["show interface ip brief", "show running-config interface"],
            "nat_config": [
                "show running-config nat",
                "show running-config object network",
                "show running-config object service",
            ],
            "tunnel": ["show vpn-sessiondb l2l", "show crypto ipsec sa", "show crypto ikev2 sa"],
        },
        "paloalto_panos": {
            "device_type": "paloalto_panos",
            "interface": ["show interface all"],
            "nat_config": [
                "show running nat-policy",
                "show config running | match nat",
            ],
            "tunnel": ["show vpn ike-sa", "show vpn ipsec-sa", "show vpn tunnel"],
        },
        "fortinet": {
            "device_type": "fortinet",
            "interface": ["get system interface", "show system interface"],
            "nat_config": [
                "show firewall vip",
                "show firewall ippool",
                "show firewall policy",
            ],
            "tunnel": ["get vpn ipsec tunnel summary", "diagnose vpn tunnel list", "get vpn ssl monitor"],
        },
        "generic": {
            "device_type": "terminal_server",
            "interface": ["show interface", "show interfaces", "show ip interface brief"],
            "nat_config": [
                "show running-config | include nat",
                "show running-config | include vip",
                "show configuration | match nat",
            ],
            "tunnel": ["show tunnel", "show vpn", "show ipsec", "show ike"],
        },
    }
    return profiles[platform]


def parse_firewall_interfaces(output, device, platform, command):
    rows = []
    current = None
    current_ips = []
    current_status = ""

    def save_current():
        if not current:
            return
        rows.append({
            "Device": device,
            "Platform": platform,
            "Record_Type": "INTERFACE",
            "Name": current,
            "Local_Address": unique_join(current_ips),
            "Global_Address": "",
            "Remote_Address": "",
            "Protocol": "",
            "Port": "",
            "Status": current_status,
            "Command": command,
            "Details": "",
        })

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        match = re.search(r"\binterface\s+(\S+)", stripped, re.IGNORECASE)
        if match and match.group(1).lower() not in {"ip-address", "name", "status"}:
            save_current()
            current = match.group(1).rstrip(",")
            current_ips = []
            current_status = ""
            continue

        match = re.search(r"^name:\s*(\S+)", stripped, re.IGNORECASE)
        if match:
            save_current()
            current = match.group(1).rstrip(",")
            current_ips = []
            current_status = ""
            continue

        match = re.search(r"^==\s*\[\s*([^\]]+)\]", stripped)
        if match:
            save_current()
            current = match.group(1).strip()
            current_ips = []
            current_status = ""
            continue

        brief_tokens = stripped.split()
        if (
            len(brief_tokens) >= 2
            and extract_ips(brief_tokens[1])
            and re.match(r"^[A-Za-z][A-Za-z0-9_.-]+(?:/|$)", brief_tokens[0])
        ):
            save_current()
            current = brief_tokens[0]
            current_ips = [extract_ips(brief_tokens[1])[0]]
            current_status = " ".join(brief_tokens[4:]) if len(brief_tokens) > 4 else ""
        elif stripped.lower().startswith(("set ip ", "ip address ", "ip:")):
            ips = extract_ips(stripped)
            current_ips.extend(ips[:1] or ips)
        elif re.search(r"\bip-address\s+", stripped, re.IGNORECASE):
            current_ips.extend(extract_ips(stripped))
        elif re.search(r"\b(state|status|line protocol):?\s+", stripped, re.IGNORECASE):
            status_match = re.search(
                r"(?:state|status|line protocol):?\s+(.+)$", stripped, re.IGNORECASE
            )
            if status_match:
                current_status = status_match.group(1).strip()
        elif re.search(r"\bis\s+(up|down)\b", stripped, re.IGNORECASE):
            current_status = stripped
        elif current is None:
            tokens = stripped.split()
            if len(tokens) >= 2 and extract_ips(tokens[1]):
                current = tokens[0]
                current_ips = [extract_ips(tokens[1])[0]]
                current_status = " ".join(tokens[4:]) if len(tokens) > 4 else ""

    save_current()
    return rows


def parse_firewall_text_rows(output, device, platform, command, record_type):
    rows = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("--", "Name", "Total", "Flags", "Interface")):
            continue

        lower = line.lower()
        if record_type == "TUNNEL":
            relevant = any(
                term in lower
                for term in ("tunnel", "vpn", "ipsec", "ike", "peer", "remote", "gateway", "phase")
            )
            if not relevant:
                continue

        ips = extract_ips(line)
        ports = re.findall(r"\b(?:tcp|udp)/?(\d{1,5})\b|\bport[=: ]+(\d{1,5})\b", line, re.IGNORECASE)
        port_values = [value for pair in ports for value in pair if value]
        status = ""
        if re.search(r"\b(up|active|established|connected|down|inactive|failed)\b", lower):
            status = line

        rows.append({
            "Device": device,
            "Platform": platform,
            "Record_Type": record_type,
            "Name": "",
            "Local_Address": ips[0] if ips else "",
            "Global_Address": ips[1] if len(ips) > 1 else "",
            "Remote_Address": ips[2] if len(ips) > 2 else "",
            "Protocol": (
                "PAT" if any(term in lower for term in ("pat", "overload", "port"))
                else ""
            ),
            "Port": unique_join(port_values),
            "Status": status,
            "Command": command,
            "Details": line,
        })
    return rows


def collect_firewall(device, username, password, platform):
    """Collect firewall interfaces/tunnels and configured NAT rules."""
    profile = firewall_profile(platform)
    connection = None
    inventory_rows = []
    nat_rule_rows = []
    try:
        print(f"\nConnecting to firewall {device['host']} ({platform})...")
        connection = connect_handler(
            device_type=profile["device_type"],
            host=device["host"],
            username=username,
            password=password,
            fast_cli=False,
        )
        hostname = get_hostname(connection)
        device_name = hostname or device["host"]

        for command in profile["interface"]:
            output = safe_send_command(connection, command, read_timeout=60)
            if output:
                inventory_rows.extend(
                    parse_firewall_interfaces(output, device_name, platform, command)
                )

        for command in profile["nat_config"]:
            output = safe_send_command(connection, command, read_timeout=60)
            if output:
                nat_rule_rows.extend(
                    parse_configured_nat_output(
                        output, device_name, platform, command
                    )
                )

        for command in profile["tunnel"]:
            output = safe_send_command(connection, command, read_timeout=60)
            if output:
                inventory_rows.extend(
                    parse_firewall_text_rows(
                        output, device_name, platform, command, "TUNNEL"
                    )
                )

    except Exception as error:
        print(f"Failed to collect firewall {device['host']}: {error}")
    finally:
        if connection:
            connection.disconnect()
    return inventory_rows, _dedupe_nat_rules(nat_rule_rows)


def collect_firewalls(hosts, username, password, platform, workers):
    results_by_host = {}
    worker_count = max(1, min(workers, len(hosts)))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                collect_firewall,
                {"host": host},
                username,
                password,
                platform,
            ): host
            for host in hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                results_by_host[host] = future.result()
            except Exception as error:
                print(f"Failed to collect firewall {host}: {error}")
                results_by_host[host] = ([], [])

    inventory_rows = [
        row
        for host in hosts
        for row in results_by_host.get(host, ([], []))[0]
    ]
    nat_rule_rows = [
        row
        for host in hosts
        for row in results_by_host.get(host, ([], []))[1]
    ]
    return inventory_rows, _dedupe_nat_rules(nat_rule_rows)


FIREWALL_FIELDS = [
    "Device", "Platform", "Record_Type", "Name", "Local_Address", "Global_Address",
    "Remote_Address", "Protocol", "Port", "Status", "Command", "Details",
]

INTERFACE_FIELDS = [
    "Device", "Interface", "Interface_Type", "Description", "VRF",
    "IPv4_Addresses", "IPv6_Addresses", "IP_Unnumbered", "Tunnel_Source",
    "Tunnel_Destination", "Tunnel_Mode", "Admin_State", "Operational_IP",
    "Line_Protocol",
]



# ---------------------------------------------------------------------------
# Display and command-line handling
# ---------------------------------------------------------------------------


def display_stp_results(results, max_mac_count, max_arp_count):
    print("\n" + "=" * 240)
    print(
        "VLAN / SVI / MAC / ARP / STP ROOT REPORT "
        f"(MAC MAX {max_mac_count}, ARP MAX {max_arp_count})"
    )
    print("=" * 240)

    current_device = ""
    for row in results:
        if row["Device"] != current_device:
            current_device = row["Device"]
            print(f"\nSwitch: {current_device}")
            print("-" * 240)
            print(
                f"{'VLAN':<8}{'VLAN Name':<20}{'SVI IP':<20}{'SVI MAC':<20}"
                f"{'MACs':<6}{'ARPs':<6}{'Traffic':<18}{'Traffic Stats':<42}"
                f"{'MAC Address':<24}{'Company':<32}{'ARP Check':<16}"
                f"{'Root':<8}{'Shutdown':<10}"
            )
            print("-" * 240)

        print(
            f"{row['VLAN']:<8}{row['VLAN_Name']:<20}{row['SVI_IP']:<20}"
            f"{row['SVI_MAC']:<20}{row['MAC_Count']:<6}{row['ARP_Count']:<6}"
            f"{row['Traffic_Check']:<18}{row['Traffic_Statistics']:<42}"
            f"{row['MAC_Address']:<24}{row['MAC_Company']:<32}"
            f"{row['ARP_Check']:<16}{row['Root_Bridge']:<8}"
            f"{row['Shutdown_Recommendation']:<10}"
        )

    root_count = sum(row["Root_Bridge"] == "YES" for row in results)
    print("\n" + "=" * 240)
    print(f"Total VLANs Processed : {len(results)}")
    print(f"Total Root VLANs      : {root_count}")
    print("=" * 240)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Collect NX-OS logical-interface/IP data and optional firewall NAT/tunnel data."
    )
    parser.add_argument("--switch-hosts", help="Comma-delimited NX-OS switch hostnames/IPs. If omitted, prompts.")
    parser.add_argument("--firewall-hosts", help="Comma-delimited firewall hostnames/IPs. If omitted, prompts.")
    parser.add_argument(
        "--firewall-platform",
        choices=("cisco_asa", "cisco_ftd", "paloalto_panos", "fortinet", "generic"),
        help="Firewall platform used for command selection.",
    )
    parser.add_argument(
        "--workers", type=int, default=DEFAULT_WORKERS,
        help=f"Maximum concurrent device sessions. Default: {DEFAULT_WORKERS}",
    )
    parser.add_argument("--csv-file", default=STP_CSV_FILE, help=f"STP CSV output. Default: {STP_CSV_FILE}")
    parser.add_argument(
        "--interface-csv-file",
        default=INTERFACE_CSV_FILE,
        help=f"NX-OS interface/IP CSV output. Default: {INTERFACE_CSV_FILE}",
    )
    parser.add_argument(
        "--nat-rules-csv-file",
        "--switch-nat-csv-file",
        dest="nat_rules_csv_file",
        default=NAT_RULE_CSV_FILE,
        help=(
            "Configured NAT/PAT rules CSV output (legacy alias: "
            f"--switch-nat-csv-file). Default: {NAT_RULE_CSV_FILE}"
        ),
    )
    parser.add_argument(
        "--firewall-csv-file",
        default=FIREWALL_CSV_FILE,
        help=f"Firewall interface/NAT/tunnel CSV output. Default: {FIREWALL_CSV_FILE}",
    )
    parser.add_argument("--mac-oid-base", default=MAC_OID_BASE, help=f"MAC OID base. Default: {MAC_OID_BASE}")
    parser.add_argument(
        "--max-mac-count", type=int, default=DEFAULT_MAX_MAC_COUNT,
        help=f"Include VLANs with at most this many MACs. Default: {DEFAULT_MAX_MAC_COUNT}",
    )
    parser.add_argument(
        "--max-arp-count", type=int, default=DEFAULT_MAX_ARP_COUNT,
        help=f"Include VLANs with at most this many ARP entries. Default: {DEFAULT_MAX_ARP_COUNT}",
    )
    parser.add_argument("--oui-file", help="Local IEEE OUI CSV file.")
    parser.add_argument("--offline", action="store_true", help="Skip IEEE OUI registry download.")
    return parser


def get_credentials(label, default_username=None, default_password=None):
    if default_username is None:
        username = input(f"{label} User ID: ").strip()
    else:
        entered = input(f"{label} User ID [{default_username}]: ").strip()
        username = entered or default_username

    if default_password is None:
        password = getpass.getpass(f"{label} password: ")
    else:
        use_same = input(f"Use the same {label.lower()} password? [Y/n]: ").strip().lower()
        password = default_password if use_same in {"", "y", "yes"} else getpass.getpass(f"{label} password: ")
    return username, password


def main():
    args = build_parser().parse_args()

    if not 1 <= args.workers <= MAX_WORKERS:
        print(f"Error: --workers must be between 1 and {MAX_WORKERS}.")
        return 2
    if not 0 <= args.max_mac_count <= 2:
        print("Error: --max-mac-count must be between 0 and 2.")
        return 2
    if not 0 <= args.max_arp_count <= 2:
        print("Error: --max-arp-count must be between 0 and 2.")
        return 2

    switch_hosts = split_hosts(args.switch_hosts) if args.switch_hosts else split_hosts(
        input("Enter NX-OS switch hostnames/IPs (comma delimited; blank to skip): ").strip()
    )
    firewall_hosts = split_hosts(args.firewall_hosts) if args.firewall_hosts else split_hosts(
        input("Enter firewall hostnames/IPs (comma delimited; blank to skip): ").strip()
    )

    if not switch_hosts and not firewall_hosts:
        print("No switches or firewalls supplied.")
        return 2

    switch_username = switch_password = None
    if switch_hosts:
        switch_username, switch_password = get_credentials("Switch")

    all_stp_results = []
    all_interface_results = []
    all_nat_rule_results = []

    if switch_hosts:
        try:
            oui_registry = load_oui_registry(args.oui_file, args.offline)
            print(f"Loaded {len(oui_registry)} IEEE OUI assignments")
        except Exception as error:
            print(f"Warning: IEEE OUI registry unavailable: {error}")
            oui_registry = {}

        (
            all_stp_results,
            all_interface_results,
            all_nat_rule_results,
        ) = collect_switches(
            switch_hosts,
            switch_username,
            switch_password,
            args,
            oui_registry,
        )

        all_stp_results = deduplicate_results(all_stp_results)
        all_stp_results.sort(key=lambda row: (row["Device"], int(row["VLAN"])))
        display_stp_results(all_stp_results, args.max_mac_count, args.max_arp_count)
        write_rows(all_stp_results, args.csv_file, STP_FIELDS)
        write_rows(all_interface_results, args.interface_csv_file, INTERFACE_FIELDS)
        print(f"STP CSV saved to: {args.csv_file}")
        print(f"NX-OS interface/IP CSV saved to: {args.interface_csv_file}")

    if firewall_hosts:
        platform = args.firewall_platform
        if not platform:
            platform = input(
                "Firewall platform [cisco_asa/cisco_ftd/paloalto_panos/fortinet/generic]: "
            ).strip().lower()
        if platform not in {"cisco_asa", "cisco_ftd", "paloalto_panos", "fortinet", "generic"}:
            print(f"Unsupported firewall platform: {platform}")
            return 2

        if switch_hosts:
            firewall_username, firewall_password = get_credentials(
                "Firewall", switch_username, switch_password
            )
        else:
            firewall_username, firewall_password = get_credentials("Firewall")

        firewall_results, firewall_nat_rules = collect_firewalls(
            firewall_hosts,
            firewall_username,
            firewall_password,
            platform,
            args.workers,
        )
        all_nat_rule_results.extend(firewall_nat_rules)

        write_rows(firewall_results, args.firewall_csv_file, FIREWALL_FIELDS)
        print(f"Firewall CSV saved to: {args.firewall_csv_file}")
        print(f"Firewall records collected: {len(firewall_results)}")

    write_rows(all_nat_rule_results, args.nat_rules_csv_file, NAT_RULE_FIELDS)
    print(f"Configured NAT/PAT rules CSV saved to: {args.nat_rules_csv_file}")
    print(f"Configured NAT/PAT rules collected: {len(all_nat_rule_results)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
