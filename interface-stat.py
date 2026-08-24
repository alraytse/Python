#!/usr/bin/env python3

import csv
import getpass
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from netmiko import ConnectHandler

COMMAND = "show interface status"
OUTPUT_CSV = "interface_down_not_shutdown.csv"
MAX_WORKERS = 10

REPORTABLE_STATES = {
    "down",
    "notconnect",
    "notconnec",
}

INTERFACE_PATTERN = re.compile(
    r"^(?P<interface>"
    r"(?:Eth|Gi|Te|Fo|Po|Hu|Twe|Ethernet|GigabitEthernet|"
    r"TenGigabitEthernet|FortyGigabitEthernet|"
    r"HundredGigE|TwentyFiveGigE|Port-channel)"
    r"\d+(?:/\d+)*"
    r")\b",
    re.IGNORECASE,
)

STATUS_PATTERN = re.compile(
    r"^(connected|notconnect|notconnec|disabled|shutdown|"
    r"err-disabled|suspended|inactive|down|unknown|"
    r"link-down|channeldown|channeldo)$",
    re.IGNORECASE,
)

INTERFACE_REPLACEMENTS = {
    "Ethernet": "Eth",
    "GigabitEthernet": "Gi",
    "TenGigabitEthernet": "Te",
    "FortyGigabitEthernet": "Fo",
    "HundredGigE": "Hu",
    "TwentyFiveGigE": "Twe",
    "Port-channel": "Po",
}

def normalize_interface_name(interface):
    for long_name, short_name in INTERFACE_REPLACEMENTS.items():
        if interface.startswith(long_name):
            return interface.replace(long_name, short_name, 1)

    return interface

def get_switch_name(connection, fallback):
    try:
        prompt = connection.find_prompt().strip()
        switch_name = prompt.rstrip("#>").strip()
        return switch_name or fallback
    except Exception:
        return fallback

def parse_interface_status(output):
    """Return interfaces that are down or not connected."""
    results = []

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        interface_match = INTERFACE_PATTERN.match(line)

        if not interface_match:
            continue

        interface = normalize_interface_name(
            interface_match.group("interface")
        )

        remainder = line[interface_match.end():].strip()
        columns = re.split(r"\s{2,}", remainder)

        status = None

        for column in columns:
            candidate = column.strip()

            if STATUS_PATTERN.fullmatch(candidate):
                status = candidate.lower()
                break

        if status in REPORTABLE_STATES:
            results.append(
                {
                    "interface": interface,
                    "state": status,
                }
            )

    return results

def write_csv(results):
    """Write qualifying interfaces to a CSV file."""
    fieldnames = [
        "switch",
        "interface",
        "state",
    ]

    with open(
        OUTPUT_CSV,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(results)

def collect_switch(switch, username, password):
    device = {
        "device_type": "cisco_ios",
        "host": switch,
        "username": username,
        "password": password,
        "fast_cli": False,
    }

    connection = None

    try:
        connection = ConnectHandler(**device)
        switch_name = get_switch_name(connection, switch)

        output = connection.send_command(
            COMMAND,
            read_timeout=60,
        )

        interfaces = parse_interface_status(output)

        return [
            {
                "switch": switch_name,
                "interface": item["interface"],
                "state": item["state"],
            }
            for item in interfaces
        ]

    except Exception as exc:
        print(f"[ERROR] {switch}: {exc}")
        return []

    finally:
        if connection:
            connection.disconnect()

def main():
    print("\n========================================")
    print("Down Interface Status Report")
    print("========================================\n")

    username = input("User ID: ").strip()
    password = getpass.getpass("Password: ")

    switch_input = input(
        "Switch hostnames/IPs, comma-delimited: "
    )

    switches = [
        switch.strip()
        for switch in switch_input.split(",")
        if switch.strip()
    ]

    if not username:
        print("No user ID provided.")
        return

    if not switches:
        print("No switches provided.")
        return

    all_results = []
    max_workers = min(MAX_WORKERS, len(switches))

    print(
        f"\nChecking {len(switches)} switch(es) "
        f"using {max_workers} worker(s)...\n"
    )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                collect_switch,
                switch,
                username,
                password,
            ): switch
            for switch in switches
        }

        for future in as_completed(futures):
            switch = futures[future]

            try:
                all_results.extend(future.result())
            except Exception as exc:
                print(f"[ERROR] {switch}: {exc}")

    all_results.sort(
        key=lambda row: (
            row["switch"].lower(),
            row["interface"].lower(),
        )
    )

    write_csv(all_results)

    print("\n========================================")
    print("Interfaces Down but Not Shutdown")
    print("========================================")

    if not all_results:
        print("No qualifying interfaces found.")
    else:
        print(f"{'Switch Name':<30} {'Interface':<20} State")
        print("-" * 65)

        for row in all_results:
            print(
                f"{row['switch']:<30} "
                f"{row['interface']:<20} "
                f"{row['state']}"
            )

    print("\n========================================")
    print(f"Switches checked: {len(switches)}")
    print(f"Qualifying interfaces: {len(all_results)}")
    print(f"CSV file: {OUTPUT_CSV}")
    print("========================================")

if __name__ == "__main__":
    main()
