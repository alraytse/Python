#!/usr/bin/env python3

import csv
import getpass
import re
import sys
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

CSV_FILE = "inventory_report.csv"

INTERFACE_RE = r"(?:Eth|Gi|Te|Po|Ethernet|GigabitEthernet|TenGigabitEthernet|Port-channel)\S+"

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

    desc_u = desc.upper()
    found = []

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

def parse_interface_status(output):
    """
    Parses:
    show interface status

    Typical format:
    Port      Name      Status       Vlan   Duplex Speed Type
    Eth1/1              connected    10     full   10G   ...
    """
    results = {}

    for line in output.splitlines():
        match = re.match(
            rf"^\s*(?P<interface>{INTERFACE_RE})\s+"
            r"(?:(?P<name>.*?)\s+)?"
            r"(?P<status>connected|notconnect|disabled|suspended|"
            r"err-disabled|xcvrd|xcvr|unknown)\s+"
            r"(?P<vlan>\S+)",
            line,
            re.IGNORECASE,
        )

        if not match:
            continue

        results[match.group("interface")] = {
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

        iface = parts[0]
        admin = parts[1]
        oper = parts[2]
        desc = parts[3] if len(parts) >= 4 else ""

        interfaces[iface] = {
            "admin": admin,
            "oper": oper,
            "desc": desc,
        }

    return interfaces

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

def parse_interface_switchport(output):
    """
    Parses:
    show interface switchport

    Extracts operational mode, native VLAN, access VLAN,
    and allowed VLANs for each interface.
    """
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
    """
    Parses MAC addresses learned on Eth, Gi, Te, and Po interfaces.
    """
    mac_count = {}

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
        mac_count[interface] = mac_count.get(interface, 0) + 1

    return mac_count

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

def main():
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    hostname = input("Switch Hostname/IP: ")

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
        print("Authentication failed.", file=sys.stderr)
        sys.exit(1)

    except NetmikoTimeoutException:
        print("Connection timed out.", file=sys.stderr)
        sys.exit(1)

    except Exception as exc:
        print(f"Connection or command failure: {exc}", file=sys.stderr)
        sys.exit(1)

    finally:
        if conn:
            conn.disconnect()

    interfaces = parse_interface_description(show_desc)
    status_data = parse_interface_status(show_status)
    switchport_data = parse_interface_switchport(show_switchport)
    mac_data = parse_mac_table(show_mac)

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
        "Notes",
    ]

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

        row = {
            "Device": hostname,
            "Management IP": mgmt_ip,
            "Interface": iface,
            "Interface Status": status_data.get(iface, {}).get("status", ""),
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
            "MAC Count": mac_data.get(iface, 0),
        }

        row["Notes"] = build_notes(row)
        rows.append(row)

    with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nCSV written to {CSV_FILE}")
    print(f"Interfaces processed: {len(rows)}")

if __name__ == "__main__":
    main()
