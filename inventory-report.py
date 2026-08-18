#!/usr/bin/env python3

import re
import csv
import getpass
from netmiko import ConnectHandler

CSV_FILE = "inventory_report.csv"


def find_vendor(desc):
    vendors = [
        "VERIZON",
        "CLINK",
        "CENTURYLINK",
        "LUMEN",
        "COMCAST",
        "ATT",
        "AT&T",
        "COGENT",
        "CHARTER",
        "SPECTRUM",
    ]

    desc_u = desc.upper()

    for vendor in vendors:
        if vendor in desc_u:
            return vendor

    return "Unknown"


def find_circuit_id(desc):
    patterns = [
        r"CID[:= ]+([A-Za-z0-9\-]+)",
        r"CIRCUIT[:= ]+([A-Za-z0-9\-]+)",
        r"\b\d{8,}\b",
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
        if keyword in desc_u:
            found.append(keyword)

    return ",".join(found)


def circuit_type(desc):
    desc_u = desc.upper()

    if "FW" in desc_u:
        return "Firewall"

    if "INTERNET" in desc_u:
        return "Internet"

    if "WAN" in desc_u:
        return "WAN"

    return ""


def directly_attached(desc):
    words = desc.split()

    if words:
        return words[0]

    return ""


def parse_interface_status(output):
    results = {}

    for line in output.splitlines():

        if line.startswith("Eth") or line.startswith("Gi") or line.startswith("Te"):

            parts = line.split()

            if len(parts) >= 3:
                interface = parts[0]

                results[interface] = {
                    "status": parts[1],
                    "vlan": parts[2]
                }

    return results


def parse_interface_description(output):
    interfaces = {}

    for line in output.splitlines():

        if re.match(r'^(Eth|Gi|Te|Po)', line):

            parts = re.split(r'\s{2,}', line.strip())

            if len(parts) >= 4:

                iface = parts[0]
                admin = parts[1]
                oper = parts[2]
                desc = parts[3]

            elif len(parts) == 3:

                iface = parts[0]
                admin = parts[1]
                oper = parts[2]
                desc = ""

            else:
                continue

            interfaces[iface] = {
                "admin": admin,
                "oper": oper,
                "desc": desc
            }

    return interfaces


def parse_mac_table(output):

    mac_count = {}

    for line in output.splitlines():

        match = re.search(
            r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}).*(Eth\S+)',
            line,
            re.IGNORECASE
        )

        if match:

            iface = match.group(2)

            mac_count[iface] = mac_count.get(iface, 0) + 1

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

    print(f"\nConnecting to {hostname}...\n")

    conn = ConnectHandler(**device)

    show_desc = conn.send_command(
        "show interface description",
        read_timeout=60
    )

    show_status = conn.send_command(
        "show interface status",
        read_timeout=60
    )

    show_mac = conn.send_command(
        "show mac address-table",
        read_timeout=60
    )

    try:
        mgmt_ip = conn.host
    except:
        mgmt_ip = hostname

    conn.disconnect()

    interfaces = parse_interface_description(show_desc)
    status_data = parse_interface_status(show_status)
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
        "Notes"
    ]

    rows = []

    for iface, data in interfaces.items():

        desc = data["desc"]

        row = {
            "Device": hostname,
            "Management IP": mgmt_ip,
            "Interface": iface,
            "Interface Status": data["oper"],
            "Admin Status": data["admin"],
            "Operational Status": data["oper"],
            "VLAN": status_data.get(iface, {}).get("vlan", ""),
            "Mode": "",
            "Native VLAN": "",
            "Allowed VLANs": "",
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

    with open(CSV_FILE, "w", newline="") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )

        writer.writeheader()

        for row in rows:
            writer.writerow(row)

    print(f"\nCSV written to {CSV_FILE}")
    print(f"Interfaces processed: {len(rows)}")


if __name__ == "__main__":
    main()