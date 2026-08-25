#!/usr/bin/env python3

import csv
import getpass
import re
from datetime import datetime

from netmiko import ConnectHandler


DEVICE_TYPES = [
    "cisco_nxos",
    "cisco_ios",
    "arista_eos",
]


def clean_terminal_output(output):
    """Remove ANSI terminal formatting from command output."""
    return re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", output)


def platform_matches(device_type, version_output):
    """Confirm that a show version response matches the Netmiko driver."""
    text = clean_terminal_output(version_output).lower()

    if not text or any(
        marker in text
        for marker in (
            "invalid command",
            "invalid input",
            "incomplete command",
            "unknown command",
            "% error",
        )
    ):
        return False

    if device_type == "cisco_nxos":
        return "nexus" in text or "nx-os" in text or "nxos" in text

    if device_type == "cisco_ios":
        return (
            ("cisco ios" in text or "ios xe" in text)
            and "nexus" not in text
        )

    if device_type == "arista_eos":
        return "arista" in text or "eos version" in text

    return False


def normalize_interface_for_device(interface, device_type):
    """Convert shorthand interface input to a device-appropriate name."""
    interface = interface.strip()

    if device_type == "arista_eos":
        # Arista Ethernet ports are commonly entered as 12 or Eth12.
        numeric_match = re.fullmatch(r"(?:eth(?:ernet)?)?(\d+)", interface, re.IGNORECASE)
        if numeric_match:
            return f"Ethernet{numeric_match.group(1)}"

    return interface

def get_interface_status(conn, interface, device_type):
    interface = normalize_interface_for_device(interface, device_type)

    if device_type == "arista_eos":
        commands = [
            f"show interfaces {interface}",
            f"show interface {interface}",
        ]
    else:
        commands = [
            f"show interface {interface}",
            f"show interfaces {interface}",
        ]

    for cmd in commands:
        try:
            output = conn.send_command(cmd, read_timeout=30)
            clean_output = clean_terminal_output(output)
            output_lower = clean_output.lower()

            invalid_markers = (
                "invalid command",
                "invalid input",
                "incomplete command",
                "unknown command",
                "% error",
            )
            if any(marker in output_lower for marker in invalid_markers):
                continue

            if "admin state is down" in output_lower:
                status = "Administratively Down"
            elif "administratively down" in output_lower:
                status = "Administratively Down"
            elif "line protocol is up" in output_lower:
                status = "Up"
            elif "line protocol is down" in output_lower:
                status = "Down"
            else:
                # Handles NX-OS and EOS lines such as:
                # Ethernet1/2 is down (linkFlapErrDisabled)
                # Ethernet1 is up, line protocol is up
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
    for device_type in DEVICE_TYPES:
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
            version_output = conn.send_command("show version", read_timeout=30)

            if not platform_matches(device_type, version_output):
                conn.disconnect()
                conn = None
                continue

            print(f"\nConnected to {hostname} ({device_type})")
            results = []

            for interface in interfaces:
                try:
                    resolved_interface = normalize_interface_for_device(
                        interface,
                        device_type,
                    )
                    status, _ = get_interface_status(
                        conn,
                        resolved_interface,
                        device_type,
                    )

                    result = {
                        "Switch": hostname,
                        "Interface": resolved_interface,
                        "Status": status,
                    }

                    results.append(result)
                    print(
                        f"{hostname:<30} {resolved_interface:<15} {status}"
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
