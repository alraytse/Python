#!/usr/bin/env python3

import getpass
import csv
import re
from netmiko import ConnectHandler

CSV_FILE = "stp_root_report.csv"


def parse_vlans(output):
    vlans = []

    for line in output.splitlines():
        match = re.match(r"^(\d+)\s+", line.strip())
        if match:
            vlans.append(match.group(1))

    return vlans


def check_root(connection, vlan):
    try:
        output = connection.send_command(
            f"show spanning-tree vlan {vlan}",
            read_timeout=30
        )

        if "This bridge is the root" in output:
            return "YES"

        if "Root ID" in output:
            return "NO"

        return "UNKNOWN"

    except Exception as e:
        return f"ERROR: {e}"


def get_hostname(connection):
    prompt = connection.find_prompt()
    return prompt.replace("#", "").replace(">", "")


def process_switch(device):
    results = []

    try:
        print(f"\nConnecting to {device['host']}...")

        conn = ConnectHandler(**device)

        hostname = get_hostname(conn)

        vlan_output = conn.send_command(
            "show vlan brief",
            read_timeout=30
        )

        vlans = parse_vlans(vlan_output)

        print(f"{hostname}: Found {len(vlans)} VLANs")

        for vlan in vlans:
            root_status = check_root(conn, vlan)

            results.append({
                "Device": hostname,
                "VLAN": vlan,
                "Root_Bridge": root_status
            })

        conn.disconnect()

    except Exception as e:
        print(f"Failed to connect to {device['host']} : {e}")

    return results


def write_csv(results):

    with open(CSV_FILE, "w", newline="") as csvfile:

        fields = [
            "Device",
            "VLAN",
            "Root_Bridge"
        ]

        writer = csv.DictWriter(csvfile, fieldnames=fields)

        writer.writeheader()

        for row in results:
            writer.writerow(row)


def display_results(results):

    print("\n" + "=" * 80)
    print("SPANNING TREE ROOT REPORT")
    print("=" * 80)

    current_device = ""

    for row in results:

        if row["Device"] != current_device:
            current_device = row["Device"]
            print(f"\nSwitch: {current_device}")

        print(
            f" VLAN {row['VLAN']:>4}   Root Bridge: {row['Root_Bridge']}"
        )


def main():

    hosts = input(
        "Enter switch hostnames/IPs (comma delimited): "
    ).strip()

    host_list = [
        h.strip() for h in hosts.split(",")
        if h.strip()
    ]

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    all_results = []

    for host in host_list:

        device = {
            "device_type": "cisco_ios",
            "host": host,
            "username": username,
            "password": password,
            "fast_cli": False
        }

        results = process_switch(device)
        all_results.extend(results)

    display_results(all_results)

    write_csv(all_results)

    print(f"\nCSV report saved to: {CSV_FILE}")


if __name__ == "__main__":
    main()