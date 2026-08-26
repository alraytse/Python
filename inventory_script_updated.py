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

INTERFACE_RE = (
    r"(?:Vlan|Eth|Gi|Te|Po|Ethernet|GigabitEthernet|TenGigabitEthernet|"
    r"Port-channel)\S+"
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
    replacements = {
        "Ethernet": "Eth",
        "GigabitEthernet": "Gi",
        "TenGigabitEthernet": "Te",
        "Port-channel": "Po",
    }

    for long_name, short_name in replacements.items():
        if interface.startswith(long_name):
            return interface.replace(long_name, short_name, 1)

    return interface


def parse_interface_status(output):
    results = {}

    for line in output.splitlines():
        match = re.match(
            rf"^\s*(?P<interface>{INTERFACE_RE})\s+"
            rf"(?:(?P<name>.*?)\s+)?"
            r"(?P<status>connected|notconnect|disabled|suspended|"
            r"err-disabled|xcvrd|xcvr|unknown)\s+"
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


def parse_svi_details(output):
    """Parse SVI IP address and status from show ip interface brief."""
    svis = {}

    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue

        interface = parts[0]
        if not re.fullmatch(r"Vlan\d+", interface, re.IGNORECASE):
            continue

        svis[normalize_interface_name(interface)] = {
            "ip_address": parts[1],
            "status": " ".join(parts[2:]),
        }

    return svis


def append_vlan_values(existing, continuation):
    """Append a wrapped VLAN value without creating duplicate separators."""
    existing = existing.strip()
    continuation = continuation.strip()

    if not continuation:
        return existing

    if not existing:
        return continuation

    return f"{existing.rstrip(',')} , {continuation.lstrip(',')}".replace(
        " , ", ","
    )


def parse_interface_switchport(output):
    """Parse switchport data, including wrapped allowed-VLAN output lines."""
    results = {}
    current_interface = None
    collecting_allowed_vlans = False

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
            collecting_allowed_vlans = False
            continue

        if not current_interface:
            continue

        # A new labeled field ends a wrapped allowed-VLAN section. Continuation
        # lines from NX-OS normally contain only VLAN IDs, ranges, and commas.
        if collecting_allowed_vlans:
            if re.match(r"^[A-Za-z][^:]*:", line):
                collecting_allowed_vlans = False
            elif line:
                results[current_interface]["allowed_vlans"] = append_vlan_values(
                    results[current_interface]["allowed_vlans"],
                    line,
                )
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
            r"^Trunking VLANs Enabled:\s*(.*)$",
            line,
            re.IGNORECASE,
        )
        if allowed_vlan_match:
            results[current_interface]["allowed_vlans"] = (
                allowed_vlan_match.group(1).strip()
            )
            collecting_allowed_vlans = True
            continue

    return results


def parse_vlan_names(output):
    """Return a mapping of VLAN ID strings to VLAN names from NX-OS output."""
    vlan_names = {}
    vlan_statuses = (
        r"active|act/unsup|act/lshut|suspended|suspend|shutdown|"
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

        vlan_id = match.group("vlan_id")
        vlan_name = match.group("name").strip()
        vlan_names[vlan_id] = vlan_name

    return vlan_names


def parse_interface_error_reason(output):
    """Extract the NX-OS interface error reason from detailed interface output."""
    for line in output.splitlines():
        match = re.search(
            r"\bis\s+(?:up|down)\s+\((?P<reason>[^)]+)\)",
            line,
            re.IGNORECASE,
        )
        if match:
            return match.group("reason").strip()

    return ""


def collect_interface_error_reasons(conn, interfaces):
    """Collect detailed error reasons without failing the host for one bad command."""
    error_reasons = {}

    for interface in interfaces:
        try:
            output = conn.send_command(
                f"show interface {interface}",
                read_timeout=30,
            )
            error_reasons[interface] = parse_interface_error_reason(output)
        except Exception as exc:
            print(
                f"{conn.host} {interface}: unable to collect interface reason: {exc}",
                file=sys.stderr,
            )
            error_reasons[interface] = ""

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

    if row["Circuit Vendor"] == "Unknown":
        notes.append("Vendor Unknown")

    if not row["Circuit IDs"]:
        notes.append("Circuit ID Missing")

    if row["MAC Count"] == 0:
        notes.append("No MAC Addresses Learned")

    return "; ".join(notes)


def collect_host(hostname, username, password):
    device = {
        "device_type": "cisco_nxos",
        "host": hostname,
        "username": username,
        "password": password,
        "fast_cli": False,
    }

    conn = None

    try:
        print(f"\nConnecting to {hostname}...\n")
        conn = ConnectHandler(**device)

        show_desc = conn.send_command(
            "show interface description",
            read_timeout=60,
        )
        show_status = conn.send_command(
            "show interface status",
            read_timeout=60,
        )
        show_switchport = conn.send_command(
            "show interface switchport",
            read_timeout=60,
        )
        show_vlan = conn.send_command(
            "show vlan brief",
            read_timeout=60,
        )
        show_mac = conn.send_command(
            "show mac address-table",
            read_timeout=60,
        )
        show_ip_interface_brief = conn.send_command(
            "show ip interface brief",
            read_timeout=60,
        )

        interfaces = parse_interface_description(show_desc)
        svi_data = parse_svi_details(show_ip_interface_brief)

        # Some NX-OS outputs omit an SVI from interface descriptions. Add any
        # SVI found in show ip interface brief so Vlan20/Vlan21 are retained.
        for svi_interface in svi_data:
            interfaces.setdefault(
                svi_interface,
                {
                    "admin": "",
                    "oper": "",
                    "desc": "",
                },
            )
        interface_error_reasons = collect_interface_error_reasons(
            conn,
            interfaces.keys(),
        )

        mgmt_ip = conn.host

    except NetmikoAuthenticationException:
        print(f"{hostname}: authentication failed.", file=sys.stderr)
        return []

    except NetmikoTimeoutException:
        print(f"{hostname}: connection timed out.", file=sys.stderr)
        return []

    except Exception as exc:
        print(f"{hostname}: connection or command failure: {exc}", file=sys.stderr)
        return []

    finally:
        if conn:
            conn.disconnect()

    status_data = parse_interface_status(show_status)
    switchport_data = parse_interface_switchport(show_switchport)
    vlan_names = parse_vlan_names(show_vlan)
    mac_data = parse_mac_table(show_mac)

    rows = []

    for iface, data in interfaces.items():
        desc = data["desc"]
        status_info = status_data.get(iface, {})
        svi_info = svi_data.get(
            iface,
            {
                "ip_address": "",
                "status": "",
            },
        )

        # NX-OS generally does not include SVI interfaces in
        # "show interface status". Infer the VLAN ID from names such as
        # Vlan20 so SVI rows still receive VLAN and VLAN Name values.
        vlan_id = status_info.get("vlan", "")
        if not vlan_id and re.fullmatch(r"Vlan(?P<vlan_id>\d+)", iface, re.IGNORECASE):
            vlan_id = re.fullmatch(
                r"Vlan(?P<vlan_id>\d+)", iface, re.IGNORECASE
            ).group("vlan_id")

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
        device_type = classify_device(desc, mac_vendors)

        row = {
            "Device": hostname,
            "Management IP": mgmt_ip,
            "Interface": iface,
            "SVI IP Address": svi_info["ip_address"],
            "SVI Status": svi_info["status"],
            "Interface Status": status_info.get("status", ""),
            "Interface Error Reason": interface_error_reasons.get(iface, ""),
            "Admin Status": data["admin"],
            "Operational Status": data["oper"],
            "VLAN": vlan_id,
            "VLAN Name": vlan_name,
            "Mode": switchport["mode"],
            "Native VLAN": switchport["native_vlan"],
            "Allowed VLANs": switchport["allowed_vlans"],
            "Circuit Vendor": find_vendor(desc),
            "Circuit IDs": find_circuit_id(desc),
            "Circuit Type": circuit_type(desc),
            "Circuit Directly Attached": directly_attached(desc),
            "Matched Keywords": find_keywords(desc),
            "Description": desc,
            "MAC Count": mac_count,
            "MAC Addresses": mac_addresses,
            "MAC Vendor": mac_vendor,
            "Device Type": device_type,
        }

        row["Notes"] = build_notes(row)
        rows.append(row)

    return rows


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
        "Device",
        "Management IP",
        "Interface",
        "SVI IP Address",
        "SVI Status",
        "Interface Status",
        "Interface Error Reason",
        "Admin Status",
        "Operational Status",
        "VLAN",
        "VLAN Name",
        "Mode",
        "Native VLAN",
        "Allowed VLANs",
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

    # Limit concurrency so large host lists do not overwhelm the workstation
    # or the network devices. Results are written in the original input order.
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
