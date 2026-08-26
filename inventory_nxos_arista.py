#!/usr/bin/env python3

import csv
import getpass
import re
import sys

from concurrent.futures import ThreadPoolExecutor, as_completed

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

try:
    from mac_vendor_lookup import MacLookup
except ImportError:
    MacLookup = None

_MAC_LOOKUP = None
if MacLookup is not None:
    try:
        _MAC_LOOKUP = MacLookup()
    except Exception:
        _MAC_LOOKUP = None


CSV_FILE = "inventory_report.csv"
DEVICE_TYPES = ("cisco_nxos", "arista_eos")

INTERFACE_RE = (
    r"(?:Ethernet|GigabitEthernet|TenGigabitEthernet|Port-channel|"
    r"Port-Channel|Eth|Et|Gi|Te|Po|Management|Ma|Vxlan)\S+"
)

INVALID_OUTPUT_MARKERS = (
    "invalid command",
    "invalid input",
    "incomplete command",
    "unknown command",
    "% error",
)


def find_vendor(desc):
    vendors = [
        ("AT&T", r"\bAT\s*&\s*T\b"),
        ("ATT", r"\bATT\b"),
        ("VERIZON", r"\bVERIZON\b"),
        ("CLINK", r"\bCLINK\b"),
        ("CENTURYLINK", r"\bCENTURYLINK\b"),
        ("LUMEN", r"\bLUMEN\b"),
        ("COMCAST", r"\bCOMCAST\b"),
        ("COGENT", r"\bCOGENT\b"),
        ("CHARTER", r"\bCHARTER\b"),
        ("SPECTRUM", r"\bSPECTRUM\b"),
    ]

    for vendor, pattern in vendors:
        if re.search(pattern, desc, re.IGNORECASE):
            return vendor

    return "Unknown"


def find_circuit_id(desc):
    patterns = [
        r"\bCID\s*[:=]?\s*([A-Za-z0-9-]+)",
        r"\bCIRCUIT\s*[:=]?\s*([A-Za-z0-9-]+)",
        r"\b(\d{8,})\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, desc, re.IGNORECASE)
        if match:
            return match.group(1)

    return ""


def find_keywords(desc):
    keywords = [
        "FW",
        "ISP",
        "INTERNET",
        "VERIZON",
        "CLINK",
        "LUMEN",
        "WAN",
        "PRISMA",
        "VPN",
        "B2B",
        "DMZ",
        "PA",
    ]

    found = []
    desc_u = desc.upper()

    for keyword in keywords:
        if re.search(rf"\b{re.escape(keyword)}\b", desc_u):
            found.append(keyword)

    return ",".join(found)


def circuit_type(desc):
    desc_u = desc.upper()

    if "INTERNET" in desc_u:
        return "Internet"

    if re.search(r"\bFW\b", desc_u):
        return "Firewall"

    if re.search(r"\bWAN\b", desc_u):
        return "WAN"

    return ""


def directly_attached(desc):
    match = re.match(r"^\s*(\S+)", desc)
    return match.group(1) if match else ""


def normalize_interface_name(interface):
    """Normalize Cisco and Arista interface abbreviations to common names."""
    interface = interface.strip()
    replacements = (
        ("Port-Channel", "Po"),
        ("Port-channel", "Po"),
        ("TenGigabitEthernet", "Te"),
        ("GigabitEthernet", "Gi"),
        ("Ethernet", "Eth"),
    )

    for long_name, short_name in replacements:
        if interface.startswith(long_name):
            return interface.replace(long_name, short_name, 1)

    # Arista uses Et1 while the common normalized form is Eth1.
    if interface.startswith("Et") and not interface.startswith("Eth"):
        return interface.replace("Et", "Eth", 1)

    return interface


def command_interface_name(interface, device_type):
    """Return a command-friendly interface name for the target platform."""
    interface = normalize_interface_name(interface)

    if device_type == "arista_eos" and interface.startswith("Eth"):
        return interface.replace("Eth", "Ethernet", 1)

    return interface


def clean_output(output):
    return re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", output or "")


def run_command(conn, commands, read_timeout=60):
    """Run command alternatives and return the first usable response."""
    for command in commands:
        try:
            output = clean_output(
                conn.send_command(command, read_timeout=read_timeout)
            )
            output_lower = output.lower()

            if output and not any(
                marker in output_lower for marker in INVALID_OUTPUT_MARKERS
            ):
                return output
        except Exception:
            continue

    return ""


def platform_matches(device_type, version_output):
    text = clean_output(version_output).lower()

    if not text or any(marker in text for marker in INVALID_OUTPUT_MARKERS):
        return False

    if device_type == "cisco_nxos":
        return "nexus" in text or "nx-os" in text or "nxos" in text

    if device_type == "arista_eos":
        return "arista" in text or "eos version" in text

    return False


def parse_interface_status(output):
    results = {}

    for line in output.splitlines():
        match = re.match(
            rf"^\s*(?P<interface>{INTERFACE_RE})\s+"
            rf"(?:(?P<name>.*?)\s+)?"
            r"(?P<status>connected|notconnect|disabled|suspended|"
            r"err-disabled|errdisabled|inactive|xcvrd|xcvr|unknown)\s+"
            r"(?P<vlan>\S+)",
            line,
            re.IGNORECASE,
        )

        if not match:
            continue

        interface = normalize_interface_name(match.group("interface"))
        results[interface] = {
            "status": match.group("status"),
            "vlan": match.group("vlan"),
        }

    return results


def parse_interface_description(output):
    interfaces = {}

    for line in output.splitlines():
        if not re.match(rf"^\s*{INTERFACE_RE}\b", line):
            continue

        parts = re.split(r"\s{2,}", line.strip())

        if len(parts) < 3:
            continue

        iface = normalize_interface_name(parts[0])
        admin = parts[1]
        oper = parts[2]
        desc = parts[3] if len(parts) >= 4 else ""

        interfaces[iface] = {
            "admin": admin,
            "oper": oper,
            "desc": desc,
        }

    return interfaces


def parse_interface_switchport(output):
    results = {}
    current_interface = None

    for raw_line in output.splitlines():
        line = raw_line.strip()

        interface_match = re.match(
            rf"^Name:\s*(?P<interface>{INTERFACE_RE})",
            line,
            re.IGNORECASE,
        )

        if interface_match:
            current_interface = normalize_interface_name(
                interface_match.group("interface")
            )
            results[current_interface] = {
                "mode": "",
                "native_vlan": "",
                "allowed_vlans": "",
            }
            continue

        if not current_interface:
            continue

        mode_match = re.match(
            r"^Operational Mode:\s*(.+)$",
            line,
            re.IGNORECASE,
        )
        if mode_match:
            results[current_interface]["mode"] = mode_match.group(1).strip()
            continue

        access_vlan_match = re.match(
            r"^Access Mode VLAN:\s*(\S+)",
            line,
            re.IGNORECASE,
        )
        if access_vlan_match:
            results[current_interface]["native_vlan"] = (
                access_vlan_match.group(1)
            )
            continue

        native_vlan_match = re.match(
            r"^Trunking Native Mode VLAN:\s*(\S+)",
            line,
            re.IGNORECASE,
        )
        if native_vlan_match:
            results[current_interface]["native_vlan"] = (
                native_vlan_match.group(1)
            )
            continue

        allowed_vlan_match = re.match(
            r"^Trunking VLANs Enabled:\s*(.+)$",
            line,
            re.IGNORECASE,
        )
        if allowed_vlan_match:
            results[current_interface]["allowed_vlans"] = (
                allowed_vlan_match.group(1).strip()
            )

    return results


def parse_vlan_names(output):
    """Return a mapping of VLAN ID strings to VLAN names."""
    vlan_names = {}
    vlan_statuses = (
        r"active|inactive|act/unsup|act/lshut|suspended|suspend|shutdown|"
        r"sus/lshut|act/unchecked"
    )

    for line in output.splitlines():
        match = re.match(
            rf"^\s*(?P<vlan_id>\d+)\s+"
            rf"(?P<name>.*?)\s+(?P<status>{vlan_statuses})\s*",
            line,
            re.IGNORECASE,
        )

        if not match:
            continue

        vlan_names[match.group("vlan_id")] = match.group("name").strip()

    return vlan_names


def expand_allowed_vlans(allowed_vlans, vlan_names):
    """Expand VLAN IDs/ranges into a readable ID-to-name list."""
    allowed_vlans = (allowed_vlans or "").strip()
    if not allowed_vlans:
        return ""

    if allowed_vlans.upper() in {"ALL", "ALL VLANs"}:
        vlan_ids = sorted(vlan_names, key=lambda value: int(value))
    else:
        vlan_ids = []
        for token in re.split(r"[, ]+", allowed_vlans):
            token = token.strip()
            if not token:
                continue

            range_match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", token)
            if range_match:
                start = int(range_match.group(1))
                end = int(range_match.group(2))
                if start <= end:
                    vlan_ids.extend(str(vlan_id) for vlan_id in range(start, end + 1))
                continue

            if token.isdigit():
                vlan_ids.append(token)

    unique_vlan_ids = []
    for vlan_id in vlan_ids:
        if vlan_id not in unique_vlan_ids:
            unique_vlan_ids.append(vlan_id)

    return ", ".join(
        f"{vlan_id}: {vlan_names.get(vlan_id, 'Unknown')}"
        for vlan_id in unique_vlan_ids
    )


def parse_interface_error_reason(output):
    """Extract a parenthesized NX-OS or EOS interface reason."""
    for line in output.splitlines():
        match = re.search(
            r"\bis\s+(?:up|down)\b.*?\((?P<reason>[^)]+)\)",
            line,
            re.IGNORECASE,
        )
        if match:
            return match.group("reason").strip()

    return ""


def collect_interface_error_reasons(conn, interfaces, device_type):
    """Collect detailed reasons without failing the host for one bad command."""
    error_reasons = {}

    for interface in interfaces:
        command_interface = command_interface_name(interface, device_type)
        output = run_command(
            conn,
            [
                f"show interfaces {command_interface}",
                f"show interface {command_interface}",
            ],
            read_timeout=30,
        )
        error_reasons[interface] = parse_interface_error_reason(output)

    return error_reasons


def parse_mac_table(output):
    mac_data = {}

    for line in output.splitlines():
        mac_match = re.search(
            r"\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b",
            line,
            re.IGNORECASE,
        )

        if not mac_match:
            continue

        interface_match = re.search(
            rf"\b(?P<interface>{INTERFACE_RE})\b",
            line,
            re.IGNORECASE,
        )

        if not interface_match:
            continue

        interface = normalize_interface_name(interface_match.group("interface"))
        mac_address = mac_match.group(0).lower()

        if interface not in mac_data:
            mac_data[interface] = {
                "count": 0,
                "addresses": [],
            }

        mac_data[interface]["count"] += 1
        mac_data[interface]["addresses"].append(mac_address)

    return mac_data


def lookup_mac_vendor(mac_address):
    """Return the manufacturer associated with a MAC OUI when available."""
    if _MAC_LOOKUP is None:
        return "Unknown"

    try:
        return _MAC_LOOKUP.lookup(mac_address)
    except Exception:
        return "Unknown"


def classify_device(description, vendors):
    """Best-effort device classification; MAC OUIs cannot identify exact models."""
    text = f"{description} {' '.join(vendors)}".upper()

    description_types = [
        ("Firewall", r"\b(FW|FIREWALL)\b"),
        ("Wireless Access Point", r"\b(AP|ACCESS POINT|WAP|WIRELESS)\b"),
        ("IP Phone", r"\b(IP PHONE|VOIP|PHONE)\b"),
        ("Printer", r"\b(PRINTER|MFP|COPIER)\b"),
        ("Camera", r"\b(CAMERA|CAM|CCTV)\b"),
        ("Server", r"\b(SERVER|ESXI|HYPERV|HYPER-V)\b"),
    ]

    for device_type, pattern in description_types:
        if re.search(pattern, description, re.IGNORECASE):
            return device_type

    if re.search(
        r"CISCO|ARISTA|JUNIPER|FORTINET|PALO ALTO|PALOALTO|"
        r"MERAKI|UBIQUITI|RUCKUS|BROCADE|EXTREME NETWORKS|HUAWEI",
        text,
    ):
        return "Network Device"

    if re.search(
        r"VMWARE|MICROSOFT|HYPER-V|QEMU|KVM|VIRTUALBOX|PARALLELS",
        text,
    ):
        return "Virtual Machine/Hypervisor"

    if re.search(
        r"HEWLETT[- ]PACKARD|HP INC|BROTHER|CANON|EPSON|LEXMARK|"
        r"RICOH|KONICA MINOLTA",
        text,
    ):
        return "Printer"

    return "Unknown"


def build_notes(row):
    notes = []

    if row["Operational Status"].lower() == "down":
        notes.append("Interface Down")

    if row["Interface Status"].lower() in {
        "err-disabled",
        "errdisabled",
        "disabled",
    }:
        notes.append("Interface Error-Disabled")

    if row["Circuit Vendor"] == "Unknown":
        notes.append("Vendor Unknown")

    if not row["Circuit IDs"]:
        notes.append("Circuit ID Missing")

    if row["MAC Count"] == 0:
        notes.append("No MAC Addresses Learned")

    return "; ".join(notes)


def collect_host(hostname, username, password):
    for device_type in DEVICE_TYPES:
        conn = None

        try:
            device = {
                "device_type": device_type,
                "host": hostname,
                "username": username,
                "password": password,
                "fast_cli": False,
            }

            print(f"\nConnecting to {hostname} ({device_type})...\n")
            conn = ConnectHandler(**device)

            version_output = run_command(
                conn,
                ["show version"],
                read_timeout=30,
            )
            if not platform_matches(device_type, version_output):
                continue

            if device_type == "arista_eos":
                desc_commands = ["show interfaces description", "show interface description"]
                status_commands = ["show interfaces status", "show interface status"]
                switchport_commands = ["show interfaces switchport", "show interface switchport"]
                vlan_commands = ["show vlan", "show vlan brief"]
            else:
                desc_commands = ["show interface description"]
                status_commands = ["show interface status", "show interfaces status"]
                switchport_commands = ["show interface switchport", "show interfaces switchport"]
                vlan_commands = ["show vlan brief", "show vlan"]

            show_desc = run_command(conn, desc_commands)
            show_status = run_command(conn, status_commands)
            show_switchport = run_command(conn, switchport_commands)
            show_vlan = run_command(conn, vlan_commands)
            show_mac = run_command(
                conn,
                ["show mac address-table", "show mac address-table dynamic"],
            )

            interfaces = parse_interface_description(show_desc)
            status_data = parse_interface_status(show_status)
            switchport_data = parse_interface_switchport(show_switchport)
            vlan_names = parse_vlan_names(show_vlan)
            interface_error_reasons = collect_interface_error_reasons(
                conn,
                interfaces.keys(),
                device_type,
            )
            mac_data = parse_mac_table(show_mac)
            mgmt_ip = conn.host

            print(f"Connected to {hostname} ({device_type})")
            rows = []

            for iface, data in interfaces.items():
                desc = data["desc"]
                status_info = status_data.get(iface, {})
                vlan_id = status_info.get("vlan", "")
                vlan_name = vlan_names.get(vlan_id, "") if vlan_id.isdigit() else ""

                switchport = switchport_data.get(
                    iface,
                    {
                        "mode": "",
                        "native_vlan": "",
                        "allowed_vlans": "",
                    },
                )

                mac_info = mac_data.get(
                    iface,
                    {
                        "count": 0,
                        "addresses": [],
                    },
                )
                mac_count = mac_info["count"]
                mac_list = mac_info["addresses"]
                mac_addresses = ", ".join(mac_list) if 0 < mac_count <= 2 else ""
                mac_vendors = []

                for mac_address in mac_list:
                    vendor = lookup_mac_vendor(mac_address)
                    if vendor != "Unknown" and vendor not in mac_vendors:
                        mac_vendors.append(vendor)

                mac_vendor = "; ".join(sorted(mac_vendors)) if mac_vendors else "Unknown"
                device_class = classify_device(desc, mac_vendors)

                allowed_vlan_names = expand_allowed_vlans(
                    switchport["allowed_vlans"],
                    vlan_names,
                )

                row = {
                    "Record Type": "Interface",
                    "Device": hostname,
                    "Management IP": mgmt_ip,
                    "Interface": iface,
                    "Interface Status": status_info.get("status", ""),
                    "Interface Error Reason": interface_error_reasons.get(iface, ""),
                    "Admin Status": data["admin"],
                    "Operational Status": data["oper"],
                    "VLAN": vlan_id,
                    "VLAN Name": vlan_name,
                    "Mode": switchport["mode"],
                    "Native VLAN": switchport["native_vlan"],
                    "Allowed VLANs": switchport["allowed_vlans"],
                    "Allowed VLAN Names": allowed_vlan_names,
                    "Circuit Vendor": find_vendor(desc),
                    "Circuit IDs": find_circuit_id(desc),
                    "Circuit Type": circuit_type(desc),
                    "Circuit Directly Attached": directly_attached(desc),
                    "Matched Keywords": find_keywords(desc),
                    "Description": desc,
                    "MAC Count": mac_count,
                    "MAC Addresses": mac_addresses,
                    "MAC Vendor": mac_vendor,
                    "Device Type": device_class,
                }

                row["Notes"] = build_notes(row)
                rows.append(row)

            # Add one standalone inventory row for every VLAN discovered.
            for vlan_id in sorted(vlan_names, key=lambda value: int(value)):
                rows.append({
                    "Record Type": "VLAN",
                    "Device": hostname,
                    "Management IP": mgmt_ip,
                    "Interface": "",
                    "Interface Status": "",
                    "Interface Error Reason": "",
                    "Admin Status": "",
                    "Operational Status": "",
                    "VLAN": vlan_id,
                    "VLAN Name": vlan_names[vlan_id],
                    "Mode": "",
                    "Native VLAN": "",
                    "Allowed VLANs": "",
                    "Allowed VLAN Names": "",
                    "Circuit Vendor": "",
                    "Circuit IDs": "",
                    "Circuit Type": "",
                    "Circuit Directly Attached": "",
                    "Matched Keywords": "",
                    "Description": "",
                    "MAC Count": "",
                    "MAC Addresses": "",
                    "MAC Vendor": "",
                    "Device Type": "",
                    "Notes": "VLAN Inventory Row",
                })

            return rows

        except NetmikoAuthenticationException:
            print(f"{hostname} ({device_type}): authentication failed.", file=sys.stderr)

        except NetmikoTimeoutException:
            print(f"{hostname} ({device_type}): connection timed out.", file=sys.stderr)

        except Exception as exc:
            print(
                f"{hostname} ({device_type}): connection or command failure: {exc}",
                file=sys.stderr,
            )

        finally:
            if conn:
                conn.disconnect()

    return []


def main():
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    host_input = input("Switch Hostname/IP(s), comma-delimited: ")

    hostnames = [
        hostname.strip()
        for hostname in host_input.split(",")
        if hostname.strip()
    ]

    if not hostnames:
        print("No hostnames provided.", file=sys.stderr)
        sys.exit(1)

    fields = [
        "Record Type",
        "Device",
        "Management IP",
        "Interface",
        "Interface Status",
        "Interface Error Reason",
        "Admin Status",
        "Operational Status",
        "VLAN",
        "VLAN Name",
        "Mode",
        "Native VLAN",
        "Allowed VLANs",
        "Allowed VLAN Names",
        "Circuit Vendor",
        "Circuit IDs",
        "Circuit Type",
        "Circuit Directly Attached",
        "Matched Keywords",
        "Description",
        "MAC Count",
        "MAC Addresses",
        "MAC Vendor",
        "Device Type",
        "Notes",
    ]

    max_workers = min(10, len(hostnames))
    rows_by_host = [None] * len(hostnames)

    print(
        f"Starting parallel collection for {len(hostnames)} device(s) "
        f"using {max_workers} worker(s)..."
    )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(collect_host, hostname, username, password): index
            for index, hostname in enumerate(hostnames)
        }

        for future in as_completed(futures):
            index = futures[future]
            hostname = hostnames[index]

            try:
                rows_by_host[index] = future.result()
            except Exception as exc:
                print(
                    f"{hostname}: unexpected collection failure: {exc}",
                    file=sys.stderr,
                )
                rows_by_host[index] = []

    all_rows = []
    for host_rows in rows_by_host:
        all_rows.extend(host_rows or [])

    with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\nCSV written to {CSV_FILE}")
    print(f"Devices processed: {len(hostnames)}")
    print(f"Interfaces processed: {len(all_rows)}")


if __name__ == "__main__":
    main()
