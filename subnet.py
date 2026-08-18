#!/usr/bin/env python3

import re
import csv
import socket
from getpass import getpass
from netmiko import ConnectHandler

OUTPUT_CSV = "inventory_report.csv"

VENDOR_KEYWORDS = {
    "VERIZON": "Verizon",
    "ATT": "AT&T",
    "AT&T": "AT&T",
    "LUMEN": "Lumen",
    "CENTURYLINK": "CenturyLink",
    "COGENT": "Cogent",
    "COMCAST": "Comcast",
    "CHARTER": "Charter",
    "ZAYO": "Zayo",
    "WINDSTREAM": "Windstream"
}

TYPE_KEYWORDS = {
    "FW": "Firewall",
    "FIREWALL": "Firewall",
    "ISP": "Internet",
    "INTERNET": "Internet",
    "MPLS": "MPLS",
    "VPN": "VPN",
    "WAN": "WAN"
}


def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return hostname


def detect_vendor(description):

    upper = description.upper()

    for keyword, vendor in VENDOR_KEYWORDS.items():
        if keyword in upper:
            return vendor

    return "Unknown"


def detect_circuit_type(description):

    upper = description.upper()

    found = []

    for keyword, circuit_type in TYPE_KEYWORDS.items():
        if keyword in upper:
            found.append(circuit_type)

    if found:
        return ",".join(sorted(set(found)))

    return "Unknown"


def matched_keywords(description):

    upper = description.upper()

    matches = []

    for keyword in TYPE_KEYWORDS:
        if keyword in upper:
            matches.append(keyword)

    for keyword in VENDOR_KEYWORDS:
        if keyword in upper:
            matches.append(keyword)

    return ",".join(sorted(set(matches)))


def find_attached_device(description):

    devices = re.findall(
        r'(DDC1-[A-Za-z0-9\-]+|USON-[A-Za-z0-9\-]+|BUMSH\d+)',
        description,
        re.IGNORECASE
    )

    if devices:
        return devices[0]

    return ""


def build_notes(status, vendor, circuit_id=""):

    notes = []

    if status.lower() not in ["connected", "up"]:
        notes.append("Interface Down")

    if vendor == "Unknown":
        notes.append("Vendor Unknown")

    if not circuit_id:
        notes.append("Circuit ID Missing")

    return "; ".join(notes)


def connect_device(host, username, password):

    return ConnectHandler(
        device_type="cisco_nxos",
        host=host,
        username=username,
        password=password,
        fast_cli=False
    )


def parse_interface_status(output):

    interfaces = {}

    lines = output.splitlines()

    for line in lines:

        line = line.rstrip()

        if not line:
            continue

        if line.startswith("--"):
            continue

        if line.startswith("Port"):
            continue

        if not re.match(r'^(Eth|Po|mgmt)', line):
            continue

        #
        # Nexus format:
        #
        # Eth1/25 DDC1-ISP-FW2 Eth1 notconnect 100 auto auto 1000baseT
        #

        parts = re.split(r'\s{2,}', line.strip())

        if len(parts) < 4:
            continue

        interface = parts[0]

        description = ""

        status = ""

        vlan = ""

        speed = ""

        if len(parts) == 6:

            description = parts[1]
            status = parts[2]
            vlan = parts[3]
            speed = parts[5]

        elif len(parts) >= 7:

            description = parts[1]
            status = parts[2]
            vlan = parts[3]
            speed = parts[5]

        else:

            continue

        interfaces[interface] = {
            "description": description.strip(),
            "status": status.strip(),
            "vlan": vlan.strip(),
            "speed": speed.strip()
        }

    return interfaces


def parse_interface_config(cfg):

    mode = ""

    native_vlan = ""

    allowed_vlans = ""

    m = re.search(
        r'switchport mode (\S+)',
        cfg,
        re.I
    )

    if m:
        mode = m.group(1)

    m = re.search(
        r'switchport trunk native vlan (\d+)',
        cfg,
        re.I
    )

    if m:
        native_vlan = m.group(1)

    m = re.search(
        r'switchport trunk allowed vlan ([0-9,\-]+)',
        cfg,
        re.I
    )

    if m:
        allowed_vlans = m.group(1)

    return mode, native_vlan, allowed_vlans


def main():

    devices = input(
        "\nEnter device names (comma separated): "
    ).strip()

    username = input(
        "Username: "
    ).strip()

    password = getpass(
        "Password: "
    )

    hosts = [x.strip() for x in devices.split(",") if x.strip()]

    report = []

    for host in hosts:

        try:

            print(f"\nConnecting to {host} ...")

            conn = connect_device(
                host,
                username,
                password
            )

            conn.disable_paging()

            mgmt_ip = resolve_ip(host)

            output = conn.send_command(
                "show interface status",
                read_timeout=120
            )

            interfaces = parse_interface_status(output)

            print(
                f"Discovered {len(interfaces)} interfaces"
            )

            for interface, data in interfaces.items():

                description = data["description"]

                try:

                    cfg = conn.send_command(
                        f"show running-config interface {interface}",
                        read_timeout=30
                    )

                except Exception:

                    cfg = ""

                mode, native_vlan, allowed_vlans = \
                    parse_interface_config(cfg)

                vendor = detect_vendor(description)

                circuit_type = detect_circuit_type(
                    description
                )

                attached_device = find_attached_device(
                    description
                )

                row = {

                    "Device": host,
                    "Management IP": mgmt_ip,
                    "Interface": interface,

                    "Interface Status": data["status"],
                    "Admin Status": data["status"],
                    "Operational Status": data["status"],

                    "VLAN": data["vlan"],
                    "Mode": mode,
                    "Native VLAN": native_vlan,
                    "Allowed VLANs": allowed_vlans,

                    "Circuit Vendor": vendor,
                    "Circuit IDs": "",

                    "Circuit Type": circuit_type,

                    "Circuit Directly Attached":
                        attached_device,

                    "Matched Keywords":
                        matched_keywords(description),

                    "Description": description,

                    "Notes":
                        build_notes(
                            data["status"],
                            vendor
                        )
                }

                report.append(row)

            conn.disconnect()

        except Exception as e:

            print(
                f"ERROR connecting to {host}: {e}"
            )

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

        "Notes"
    ]

    with open(
        OUTPUT_CSV,
        "w",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )

        writer.writeheader()
        writer.writerows(report)

    print("\n---------------------------------")
    print(f"CSV written to {OUTPUT_CSV}")
    print(f"Interfaces processed: {len(report)}")
    print("---------------------------------")


if __name__ == "__main__":
    main()