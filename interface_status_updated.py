#!/usr/bin/env python3

import csv
import getpass
import re
from datetime import datetime

from netmiko import ConnectHandler


def get_interface_status(conn, interface):
    commands = [
        f"show interface {interface}",
        f"show interfaces {interface}",
    ]

    for cmd in commands:
        try:
            output = conn.send_command(cmd, read_timeout=30)

            # Remove terminal formatting that can interfere with matching.
            clean_output = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", output)
            output_lower = clean_output.lower()

            # Do not treat unsupported-command output as a valid response.
            invalid_markers = (
                "invalid command",
                "invalid input",
                "incomplete command",
                "unknown command",
                "% error",
            )
            if any(marker in output_lower for marker in invalid_markers):
                continue

            # Check administrative state before operational state.
            if "admin state is down" in output_lower:
                status = "Administratively Down"
            elif "administratively down" in output_lower:
                status = "Administratively Down"
            elif "line protocol is up" in output_lower:
                status = "Up"
            elif "line protocol is down" in output_lower:
                status = "Down"
            else:
                # NX-OS commonly reports:
                # "Ethernet1/2 is down (linkFlapErrDisabled)".
                # Search the complete response instead of requiring the
                # interface line to begin at column one.
                interface_state_match = re.search(
                    r"(?:^|\n)\s*(?:interface\s+)?"
                    r"(?:eth|ethernet|gi|gigabitethernet|te|"
                    r"tengigabitethernet|po|port-channel)\S*"
                    r"\s+is\s+(?P<state>up|down)\b",
                    output_lower,
                    re.IGNORECASE,
                )

                if interface_state_match:
                    status = interface_state_match.group("state").capitalize()
                else:
                    status = "Unknown"

            return status, clean_output

        except Exception:
            continue

    return "Failed", "Unable to retrieve interface information"


def connect_and_check(hostname, username, password, interfaces):
    device_types = [
        "cisco_nxos",
        "cisco_ios",
        "arista_eos",
    ]

    for device_type in device_types:
        conn = None

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
                        "Status": status,
                    }

                    results.append(result)

                    print(
                        f"{hostname:<30} {interface:<15} {status}"
                    )

                except Exception as exc:
                    result = {
                        "Switch": hostname,
                        "Interface": interface,
                        "Status": f"Error: {exc}",
                    }

                    results.append(result)

            return results

        except Exception:
            continue

        finally:
            if conn:
                conn.disconnect()

    return [{
        "Switch": hostname,
        "Interface": "",
        "Status": "Connection Failed",
    }]


def main():
    username = input("Username: ")
    password = getpass.getpass("Password: ")

    switches = [
        switch.strip()
        for switch in input(
            "Enter switches (comma delimited): "
        ).split(",")
        if switch.strip()
    ]

    interfaces = [
        interface.strip()
        for interface in input(
            "Enter interfaces (comma delimited): "
        ).split(",")
        if interface.strip()
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
            interfaces,
        )

        all_results.extend(results)

    with open(csv_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "Switch",
                "Interface",
                "Status",
            ],
        )

        writer.writeheader()
        writer.writerows(all_results)

    print(f"\nResults saved to: {csv_file}")


if __name__ == "__main__":
    main()
