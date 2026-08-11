#!/usr/bin/env python3

"""
Circuit Discovery Tool

Purpose
-------
Prompt for a comma-delimited list of Cisco devices, SSH to each device,
run 'show interface description', search for circuit-related keywords,
and export results to CSV.

Outputs
-------
Device
IP/Hostname
Interface
Status (up/down only)
Circuit Vendor
Circuit Directly Attached
Matched Keywords
Description

Requirements
------------
pip install netmiko
"""

import csv
import re
import getpass
from datetime import datetime

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

SEARCH_KEYWORDS = [
    "LUMEN",
    "ATT",
    "MPLS",
    "CENTURYLINK",
    "CLINK",
    "METRO",
    "METRO-E",
    "FIREWALL",
    "FW",
    "INTERNET",
    "VERIZON",
    "UPLINK",
]

OUTPUT_FILE = (
    f"circuit_discovery_"
    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
)


def determine_vendor(description):
    """Determine carrier/vendor from description."""

    desc = description.upper()

    if "VERIZON" in desc:
        return "Verizon"

    if "LUMEN" in desc:
        return "Lumen"

    if "CENTURYLINK" in desc:
        return "CenturyLink"

    if "CLINK" in desc:
        return "CenturyLink"

    if "ATT" in desc:
        return "AT&T"

    return ""


def determine_directly_attached(description):
    """
    Attempt to identify neighboring device from description.
    """

    patterns = [
        r"(DDC1-[A-Z0-9\-_]+)",
        r"(DDC-[A-Z0-9\-_]+)"
    ]

    for pattern in patterns:
        match = re.search(
            pattern,
            description,
            re.IGNORECASE
        )

        if match:
            return match.group(1)

    return ""


def normalize_status(status, protocol):
    """
    Normalize interface state to up/down only.
    """

    status = status.lower()
    protocol = protocol.lower()

    if status == "up" and protocol == "up":
        return "up"

    return "down"


def parse_interface_descriptions(output):
    """
    Parse Cisco IOS/NXOS 'show interface description' output.
    """

    interfaces = []

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.lower().startswith("interface"):
            continue

        if "----" in line:
            continue

        parts = re.split(r"\s{2,}", line)

        if len(parts) < 4:
            continue

        status = normalize_status(
            parts[1],
            parts[2]
        )

        interfaces.append(
            {
                "interface": parts[0],
                "status": status,
                "description": " ".join(parts[3:])
            }
        )

    return interfaces


def find_matches(output):

    results = []

    interfaces = parse_interface_descriptions(output)

    for interface in interfaces:

        desc_upper = interface["description"].upper()

        matched_keywords = []

        for keyword in SEARCH_KEYWORDS:

            if keyword in desc_upper:
                matched_keywords.append(keyword)

        if matched_keywords:

            results.append(
                {
                    "Interface": interface["interface"],
                    "Status": interface["status"],
                    "Description": interface["description"],
                    "Matched Keywords":
                        ",".join(
                            sorted(set(matched_keywords))
                        ),
                }
            )

    return results


def connect_to_device(host, username, password):

    records = []

    device = {
        "device_type": "cisco_ios",
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False,
    }

    try:

        print(f"\n[INFO] Connecting to {host}")

        conn = ConnectHandler(**device)

        try:
            hostname = conn.find_prompt().rstrip("#>")
        except Exception:
            hostname = host

        output = conn.send_command(
            "show interface description",
            read_timeout=120
        )

        conn.disconnect()

        matches = find_matches(output)

        print(
            f"[INFO] {hostname}: "
            f"{len(matches)} matching interface(s)"
        )

        for match in matches:

            records.append(
                {
                    "Device": hostname,
                    "IP/Hostname": host,
                    "Interface": match["Interface"],
                    "Status": match["Status"],
                    "Circuit Vendor":
                        determine_vendor(
                            match["Description"]
                        ),
                    "Circuit Directly Attached":
                        determine_directly_attached(
                            match["Description"]
                        ),
                    "Matched Keywords":
                        match["Matched Keywords"],
                    "Description":
                        match["Description"],
                }
            )

    except NetmikoAuthenticationException:

        print(
            f"[ERROR] Authentication failed: "
            f"{host}"
        )

        records.append(
            {
                "Device": host,
                "IP/Hostname": host,
                "Interface": "",
                "Status": "",
                "Circuit Vendor": "",
                "Circuit Directly Attached": "",
                "Matched Keywords": "",
                "Description": "AUTHENTICATION FAILED",
            }
        )

    except NetmikoTimeoutException:

        print(
            f"[ERROR] Connection timeout: "
            f"{host}"
        )

        records.append(
            {
                "Device": host,
                "IP/Hostname": host,
                "Interface": "",
                "Status": "",
                "Circuit Vendor": "",
                "Circuit Directly Attached": "",
                "Matched Keywords": "",
                "Description": "CONNECTION TIMEOUT",
            }
        )

    except Exception as exc:

        print(
            f"[ERROR] {host}: {exc}"
        )

        records.append(
            {
                "Device": host,
                "IP/Hostname": host,
                "Interface": "",
                "Status": "",
                "Circuit Vendor": "",
                "Circuit Directly Attached": "",
                "Matched Keywords": "",
                "Description": f"ERROR: {exc}",
            }
        )

    return records


def write_csv(records):

    fieldnames = [
        "Device",
        "IP/Hostname",
        "Interface",
        "Status",
        "Circuit Vendor",
        "Circuit Directly Attached",
        "Matched Keywords",
        "Description",
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8",
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(records)

    print("\n" + "=" * 80)
    print(f"CSV Report Written: {OUTPUT_FILE}")
    print(f"Total Records: {len(records)}")
    print("=" * 80)


def main():

    print("\nCircuit Discovery Tool")
    print("=" * 80)

    print("\nSearching for:")
    print(", ".join(SEARCH_KEYWORDS))

    hosts_input = input(
        "\nEnter comma-delimited hostnames/IPs: "
    ).strip()

    hosts = [
        host.strip()
        for host in hosts_input.split(",")
        if host.strip()
    ]

    if not hosts:
        print("No hosts provided.")
        return

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    all_records = []

    for host in hosts:

        results = connect_to_device(
            host,
            username,
            password
        )

        all_records.extend(results)

    write_csv(all_records)

    print("\nCompleted Successfully.")


if __name__ == "__main__":
    main()
