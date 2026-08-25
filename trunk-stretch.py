#!/usr/bin/env python3

import getpass
import csv
from netmiko import ConnectHandler
from datetime import datetime

def get_interface_status(conn, interface):
    commands = [
        f"show interface {interface}",
        f"show interfaces {interface}"
    ]

    for cmd in commands:
        try:
            output = conn.send_command(cmd, read_timeout=30)

            status = "Unknown"

            if "line protocol is up" in output.lower():
                status = "Up"
            elif "line protocol is down" in output.lower():
                status = "Down"
            elif "administratively down" in output.lower():
                status = "Administratively Down"

            return status, output

        except Exception:
            continue

    return "Failed", "Unable to retrieve interface information"


def connect_and_check(hostname, username, password, interfaces):

    device_types = [
        "cisco_nxos",
        "cisco_ios",
        "arista_eos"
    ]

    for device_type in device_types:

        try:
            device = {
                "device_type": device_type,
                "host": hostname,
                "username": username,
                "password": password,
                "fast_cli": False,
            }

            conn = ConnectHandler(**device)

            print(f"\nConnected to {hostname} ({device_type})")

            results = []

            for interface in interfaces:

                try:
                    status, output = get_interface_status(conn, interface)

                    result = {
                        "Switch": hostname,
                        "Interface": interface,
                        "Status": status
                    }

                    results.append(result)

                    print(
                        f"{hostname:<30} {interface:<15} {status}"
                    )

                except Exception as e:

                    result = {
                        "Switch": hostname,
                        "Interface": interface,
                        "Status": f"Error: {e}"
                    }

                    results.append(result)

            conn.disconnect()
            return results

        except Exception:
            continue

    return [{
        "Switch": hostname,
        "Interface": "",
        "Status": "Connection Failed"
    }]


def main():

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    switches = [
        x.strip()
        for x in input(
            "Enter switches (comma delimited): "
        ).split(",")
        if x.strip()
    ]

    interfaces = [
        x.strip()
        for x in input(
            "Enter interfaces (comma delimited): "
        ).split(",")
        if x.strip()
    ]

    csv_file = (
        f"interface_status_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

    all_results = []

    print("\nGathering interface status...\n")

    for switch in switches:

        results = connect_and_check(
            switch,
            username,
            password,
            interfaces
        )

        all_results.extend(results)

    with open(csv_file, "w", newline="") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "Switch",
                "Interface",
                "Status"
            ]
        )

        writer.writeheader()
        writer.writerows(all_results)

    print(f"\nResults saved to: {csv_file}")


if __name__ == "__main__":
    main()