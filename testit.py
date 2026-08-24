#!/usr/bin/env python3

import csv
import re
import getpass
from datetime import datetime

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

OUTPUT_FILE = (
    f"precheck_report_"
    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
)


def load_csv(filename):
    """
    CSV Format:
    Switch Name,Port
    DDC1-ISP-DSW1,Eth1/4
    DDC1-ISP-DSW1,Eth1/8
    """

    inventory = {}

    with open(filename, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)

        for row in reader:
            switch = row["Switch Name"].strip()
            interface = row["Port"].strip()

            inventory.setdefault(switch, []).append(interface)

    return inventory


def connect_device(host, username, password):

    device = {
        "device_type": "cisco_nxos",
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False,
    }

    return ConnectHandler(**device)


def count_macs(output):

    regex = r"([0-9a-f]{4}\.){2}[0-9a-f]{4}"

    count = 0

    for line in output.splitlines():
        if re.search(regex, line, re.I):
            count += 1

    return count


def evaluate_interface(conn, interface):

    result = {
        "status": "",
        "description": "",
        "admin_state": "",
        "mode": "",
        "port_channel": "NO",
        "mac_count": 0,
        "cdp": "NO",
        "lldp": "NO",
        "recommendation": "",
    }

    try:

        status_output = conn.send_command(
            f"show interface status | include {interface}"
        )

        result["status"] = status_output

        desc_output = conn.send_command(
            f"show interface description | include {interface}"
        )

        result["description"] = desc_output

        run_output = conn.send_command(
            f"show running-config interface {interface}"
        )

        #
        # Interface already administratively down
        #
        if re.search(r"^\s*shutdown$", run_output, re.M):

            result["admin_state"] = "SHUTDOWN"
            result["recommendation"] = "ALREADY_SHUTDOWN"

            return result

        result["admin_state"] = "NO SHUTDOWN"

        #
        # Access / Trunk
        #
        if "switchport mode trunk" in run_output:
            result["mode"] = "TRUNK"

        elif "switchport mode access" in run_output:
            result["mode"] = "ACCESS"

        else:
            result["mode"] = "UNKNOWN"

        #
        # Port-channel membership
        #
        po_output = conn.send_command(
            f"show port-channel summary | include {interface}"
        )

        if po_output.strip():
            result["port_channel"] = "YES"

        #
        # MACs
        #
        mac_output = conn.send_command(
            f"show mac address-table interface {interface}"
        )

        result["mac_count"] = count_macs(mac_output)

        #
        # CDP
        #
        cdp_output = conn.send_command(
            f"show cdp neighbors interface {interface}"
        )

        if (
            "Device ID" in cdp_output
            or "device id" in cdp_output.lower()
        ):
            result["cdp"] = "YES"

        #
        # LLDP
        #
        lldp_output = conn.send_command(
            f"show lldp neighbors interface {interface}"
        )

        if (
            "Device ID" in lldp_output
            or "Local Intf" in lldp_output
            or "Port ID" in lldp_output
        ):
            result["lldp"] = "YES"

        #
        # Recommendation logic
        #
        safe = True

        if "connected" in status_output.lower():
            safe = False

        if result["port_channel"] == "YES":
            safe = False

        if result["mode"] == "TRUNK":
            safe = False

        if result["mac_count"] > 0:
            safe = False

        if result["cdp"] == "YES":
            safe = False

        if result["lldp"] == "YES":
            safe = False

        if safe:
            result["recommendation"] = "SAFE_TO_SHUTDOWN"
        else:
            result["recommendation"] = "REVIEW_REQUIRED"

    except Exception as e:

        result["recommendation"] = f"ERROR: {str(e)}"

    return result


def main():

    print("\n=== Down Interface Precheck Utility ===\n")

    csv_file = input(
        "CSV File: "
    ).strip()

    username = input(
        "Username: "
    ).strip()

    password = getpass.getpass(
        "Password: "
    )

    switch_filter = input(
        "\nComma Delimited Switch List "
        "(blank = all switches): "
    ).strip()

    inventory = load_csv(csv_file)

    if switch_filter:

        allowed_switches = {
            x.strip().upper()
            for x in switch_filter.split(",")
            if x.strip()
        }

        inventory = {
            sw: interfaces
            for sw, interfaces in inventory.items()
            if sw.upper() in allowed_switches
        }

    with open(
        OUTPUT_FILE,
        "w",
        newline=""
    ) as outfile:

        writer = csv.writer(outfile)

        writer.writerow([
            "Switch",
            "Interface",
            "Admin_State",
            "Status",
            "Description",
            "Mode",
            "PortChannel",
            "MAC_Count",
            "CDP",
            "LLDP",
            "Recommendation",
        ])

        for switch in inventory:

            print(f"\nConnecting to {switch}")

            try:

                conn = connect_device(
                    switch,
                    username,
                    password,
                )

                for interface in inventoryprint(
                        f"  Checking {interface}"
                    )

                    result = evaluate_interface(
                        conn,
                        interface,
                    )

                    writer.writerow([
                        switch,
                        interface,
                        result["admin_state"],
                        result["status"],
                        result["description"],
                        result["mode"],
                        result["port_channel"],
                        result["mac_count"],
                        result["cdp"],
                        result["lldp"],
                        result["recommendation"],
                    ])

                conn.disconnect()

            except NetmikoAuthenticationException:

                print(
                    f"Authentication Failure: {switch}"
                )

            except NetmikoTimeoutException:

                print(
                    f"Timeout: {switch}"
                )

            except Exception as e:

                print(
                    f"Error connecting to "
                    f"{switch}: {e}"
                )

    print("\nCompleted.")
    print(f"Report: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()