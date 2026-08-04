#!/usr/bin/env python3

import csv
import getpass
import re
from netmiko import ConnectHandler

CSV_FILE = "stp_root_report.csv"


def parse_vlans(output):
    vlans = []

    for line in output.splitlines():
        match = re.match(r"^(\d+)\s+(\S+)", line.strip())

        if match:
            vlans.append({
                "vlan": match.group(1),
                "name": match.group(2)
            })

    return vlans


def check_root(connection, vlan):
    try:
        output = connection.send_command(
            f"show spanning-tree vlan {vlan}",
            read_timeout=30
        )

        return "This bridge is the root" in output

    except Exception as e:
        print(f"Error checking VLAN {vlan}: {e}")
        return False


def get_hostname(connection):
    prompt = connection.find_prompt()
    return prompt.replace("#", "").replace(">", "").strip()


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

        for vlan_info in vlans:

            vlan_id = vlan_info["vlan"]
            vlan_name = vlan_info["name"]

            if check_root(conn, vlan_id):

                results.append({
                    "Device": hostname,
                    "VLAN": vlan_id,
                    "VLAN_Name": vlan_name,
                    "Root_Bridge": "YES"
                })

        conn.disconnect()

    except Exception as e:
        print(f"Failed to connect to {device['host']} : {e}")

    return results


def display_results(results):

    print("\n" + "=" * 80)
    print("SPANNING TREE ROOT VLAN REPORT")
    print("=" * 80)

    current_device = ""

    for row in results:

        if row["Device"] != current_device:
            current_device = row["Device"]
            print(f"\nSwitch: {current_device}")

        print(
            f" VLAN {row['VLAN']:>4}   "
            f"Name: {row['VLAN_Name']}"
        )


def write_csv(results):

    fields = [
        "Device",
        "VLAN",
        "VLAN_Name",
        "Root_Bridge"
    ]

    with open(CSV_FILE, "w", newline="") as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fields
        )

        writer.writeheader()

        for row in results:
            writer.writerow(row)


def main():

    hosts = input(
        "\nEnter switch hostnames/IPs (comma delimited): "
    ).strip()

    host_list = [
        host.strip()
        for host in hosts.split(",")
        if host.strip()
    ]

    if not host_list:
        print("No hosts entered.")
        return

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    all_results = []

    for host in host_list:

        device = {
            "device_type": "cisco_nxos",
            "host": host,
            "username": username,
            "password": password,
            "fast_cli": False
        }

        results = process_switch(device)
        all_results.extend(results)

    all_results.sort(
        key=lambda x: (
            x["Device"],
            int(x["VLAN"])
        )
    )

    display_results(all_results)

    write_csv(all_results)

    print(f"\nCSV report saved to: {CSV_FILE}")


if __name__ == "__main__":
    main()
