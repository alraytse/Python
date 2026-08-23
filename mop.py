#!/usr/bin/env python3

import csv
import getpass
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from netmiko import ConnectHandler

OUTPUT_CSV = "bgp_neighbors.csv"


def detect_platform(connection):
    """
    Detect device platform.
    """

    try:
        output = connection.send_command(
            "show version",
            read_timeout=30
        )

        if "NX-OS" in output:
            return "cisco_nxos"

        if "Arista" in output:
            return "arista_eos"

        return "cisco_ios"

    except Exception:
        return "cisco_ios"


def get_hostname(connection):

    try:
        return connection.find_prompt().rstrip("#>")
    except Exception:
        return "UNKNOWN"


def get_bgp_config(connection):
    """
    Obtain router bgp line and ASN.
    """

    commands = [
        "show running-config | sec router bgp",
        "show run | sec router bgp"
    ]

    for cmd in commands:

        try:

            output = connection.send_command(
                cmd,
                read_timeout=30
            )

            match = re.search(
                r"^(router bgp\s+(\d+))",
                output,
                re.MULTILINE | re.IGNORECASE
            )

            if match:

                router_bgp = match.group(1).strip()
                local_asn = match.group(2).strip()

                return local_asn, router_bgp

        except Exception:
            pass

    return "UNKNOWN", "NOT_FOUND"


def get_bgp_summary(connection):
    """
    Attempt several platform-specific BGP commands.
    """

    commands = [
        "show bgp summary",
        "show ip bgp summary",
        "show bgp ipv4 unicast summary",
        "show bgp vrf all summary"
    ]

    for cmd in commands:

        try:

            output = connection.send_command(
                cmd,
                read_timeout=60
            )

            if (
                output
                and "Invalid command" not in output
                and "% Invalid" not in output
                and "Incomplete command" not in output
            ):
                return output

        except Exception:
            pass

    return None


def parse_bgp_summary(hostname, local_asn, router_bgp, output):

    records = []

    for line in output.splitlines():

        line = line.strip()

        if not re.match(r"^\d+\.\d+\.\d+\.\d+", line):
            continue

        fields = line.split()

        if len(fields) < 8:
            continue

        try:

            neighbor = fields[0]
            remote_as = fields[2]
            last_field = fields[-1]

            prefixes_received = ""

            if last_field.isdigit():
                state = "Established"
                prefixes_received = last_field
            else:
                state = last_field

            records.append({
                "device": hostname,
                "router_bgp": router_bgp,
                "local_asn": local_asn,
                "neighbor": neighbor,
                "remote_as": remote_as,
                "state": state,
                "prefixes_received": prefixes_received,
                "raw_line": line
            })

        except Exception:
            continue

    return records


def process_device(device_ip, username, password):

    results = []

    device = {
        "device_type": "cisco_ios",
        "host": device_ip,
        "username": username,
        "password": password,
        "fast_cli": False,
    }

    try:

        conn = ConnectHandler(**device)

        platform = detect_platform(conn)

        conn.disconnect()

        device["device_type"] = platform

        conn = ConnectHandler(**device)

        hostname = get_hostname(conn)

        print(f"[INFO] Connected to {hostname} ({device_ip})")

        local_asn, router_bgp = get_bgp_config(conn)

        bgp_output = get_bgp_summary(conn)

        if bgp_output:

            records = parse_bgp_summary(
                hostname,
                local_asn,
                router_bgp,
                bgp_output
            )

            if records:
                results.extend(records)
            else:
                results.append({
                    "device": hostname,
                    "router_bgp": router_bgp,
                    "local_asn": local_asn,
                    "neighbor": "",
                    "remote_as": "",
                    "state": "NO_NEIGHBORS_FOUND",
                    "prefixes_received": "",
                    "raw_line": ""
                })

        else:

            results.append({
                "device": hostname,
                "router_bgp": router_bgp,
                "local_asn": local_asn,
                "neighbor": "",
                "remote_as": "",
                "state": "BGP_NOT_CONFIGURED",
                "prefixes_received": "",
                "raw_line": ""
            })

        conn.disconnect()

    except Exception as e:

        print(f"[ERROR] {device_ip}: {e}")

        results.append({
            "device": device_ip,
            "router_bgp": "",
            "local_asn": "",
            "neighbor": "",
            "remote_as": "",
            "state": f"ERROR: {e}",
            "prefixes_received": "",
            "raw_line": ""
        })

    return results


def write_csv(results):

    fieldnames = [
        "device",
        "router_bgp",
        "local_asn",
        "neighbor",
        "remote_as",
        "state",
        "prefixes_received",
        "raw_line"
    ]

    with open(
        OUTPUT_CSV,
        "w",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)


def main():

    print("\n================================")
    print("BGP Neighbor Audit Tool")
    print("================================\n")

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    switches = input(
        "\nEnter switch hostnames/IPs (comma separated): "
    )

    device_list = [
        x.strip()
        for x in switches.split(",")
        if x.strip()
    ]

    if not device_list:
        print("No devices entered.")
        return

    all_results = []

    with ThreadPoolExecutor(max_workers=10) as executor:

        futures = {
            executor.submit(
                process_device,
                device,
                username,
                password
            ): device
            for device in device_list
        }

        for future in as_completed(futures):

            try:
                all_results.extend(
                    future.result()
                )
            except Exception as e:
                print(e)

    write_csv(all_results)

    idle_count = sum(
        1
        for r in all_results
        if str(r["state"]).lower() == "idle"
    )

    established_count = sum(
        1
        for r in all_results
        if str(r["state"]).lower() == "established"
    )

    print("\n================================")
    print("Collection Complete")
    print("================================")
    print(f"CSV File           : {OUTPUT_CSV}")
    print(f"Total Records      : {len(all_results)}")
    print(f"Established Peers  : {established_count}")
    print(f"Idle Peers         : {idle_count}")


if __name__ == "__main__":
    main()