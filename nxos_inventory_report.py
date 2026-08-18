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
    r"(?:Eth|Gi|Te|Po|Ethernet|GigabitEthernet|TenGigabitEthernet|"
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


def display_interface_status(interface, status):
    """Format port-channel state as PoX/up or PoX/down."""
    status = status.lower().strip()

    if interface.startswith("Po"):
        if status == "connected":
            return f"{interface}/up"

        if status in {
            "notconnect",
            "disabled",
            "suspended",
            "err-disabled",
            "unknown",
        }:
            return f"{interface}/down"

    return status


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
        show_mac = conn.send_command(
            "show mac address-table",
            read_timeout=60,
        )

        mgmt_ip = conn.host

    except NetmikoAuthenticationException:
        print(f"{hostname}: authentication failed.", file=sys.stderr)
        return []

    except NetmikoTimeoutException:
        print(f"{hostname}: connection timed out.", file=sys.stderr)
        return []

    except Exception as exc:
        print(
            f"{hostname}: connection or command failure: {exc}",
            file=sys.stderr,
        )
        return []

    finally:
        if conn:
            conn.disconnect()

    interfaces = parse_interface_description(show_desc)
    status_data = parse_interface_status(show_status)
    switchport_data = parse_interface_switchport(show_switchport)
    mac_data = parse_mac_table(show_mac)

    rows = []

    for iface, data in interfaces.items():
        desc = data["desc"]
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
        raw_interface_status = status_data.get(iface, {}).get("status", "")
        interface_status = display_interface_status(
            iface,
            raw_interface_status,
        )

        row = {
            "Device": hostname,
            "Management IP": mgmt_ip,
            "Interface": iface,
            "Interface Status": interface_status,
            "Admin Status": data["admin"],
            "Operational Status": data["oper"],
            "VLAN": status_data.get(iface, {}).get("vlan", ""),
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
        "Interface Status",
        "Admin Status",
        "Operational Status",
        "VLAN",
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
