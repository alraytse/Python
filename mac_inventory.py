#!/usr/bin/env python3

import csv
import re
import socket
from getpass import getpass

from netmiko import ConnectHandler


OUTPUT_CSV = "inventory_report.csv"

MAC_PATTERN = re.compile(
    r"\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b"
    r"|\b(?:[0-9A-F]{4}\.){2}[0-9A-F]{4}\b",
    re.IGNORECASE,
)


def normalize_mac(mac):
    """Return a MAC address using uppercase, colon-separated notation."""
    value = re.sub(r"[^0-9A-Fa-f]", "", mac)

    if len(value) != 12:
        return mac.upper()

    return ":".join(value[i:i + 2].upper() for i in range(0, 12, 2))


def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return hostname


def connect_device(host, username, password):
    return ConnectHandler(
        device_type="cisco_nxos",
        host=host,
        username=username,
        password=password,
        fast_cli=False,
    )


def get_interfaces(conn):
    """Return interfaces shown by Cisco NX-OS show interface status."""
    output = conn.send_command(
        "show interface status",
        read_timeout=120,
    )

    interfaces = []

    for line in output.splitlines():
        line = line.strip()

        if not re.match(r"^(Eth|Po|mgmt)", line, re.IGNORECASE):
            continue

        parts = re.split(r"\s{2,}", line)

        if parts:
            interfaces.append(parts[0])

    return interfaces


def get_mac_addresses(conn, interface):
    """Return unique MAC addresses learned on an interface."""
    try:
        output = conn.send_command(
            f"show mac address-table interface {interface}",
            read_timeout=60,
        )

        mac_addresses = MAC_PATTERN.findall(output)

        return sorted({normalize_mac(mac) for mac in mac_addresses})

    except Exception as error:
        print(f"MAC lookup failed for {interface}: {error}")
        return []


def main():
    devices = input(
        "Enter device names (comma separated): "
    ).strip()
    username = input("Username: ").strip()
    password = getpass("Password: ")

    report = []
    hosts = [host.strip() for host in devices.split(",") if host.strip()]

    for host in hosts:
        conn = None

        try:
            print(f"Connecting to {host} ...")

            conn = connect_device(host, username, password)
            conn.disable_paging()

            # Resolve the management IP to confirm the device is reachable.
            resolve_ip(host)

            for interface in get_interfaces(conn):
                mac_addresses = get_mac_addresses(conn, interface)

                # Display MAC addresses only when the interface has two or fewer.
                mac_value = (
                    ", ".join(mac_addresses)
                    if len(mac_addresses) <= 2
                    else ""
                )

                if len(mac_addresses) <= 2:
                    print(
                        f"{host} {interface} MAC addresses: "
                        f"{mac_value or 'None'}"
                    )

                report.append({
                    "Device": host,
                    "Interface": interface,
                    "MAC Addresses": mac_value,
                })

        except Exception as error:
            print(f"{host}: {error}")

        finally:
            if conn:
                conn.disconnect()

    fields = [
        "Device",
        "Interface",
        "MAC Addresses",
    ]

    with open(
        OUTPUT_CSV,
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(report)

    print(f"CSV written to {OUTPUT_CSV}")
    print(f"Interfaces processed: {len(report)}")


if __name__ == "__main__":
    main()
