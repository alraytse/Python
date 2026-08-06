#!/usr/bin/env python3

from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from datetime import datetime
import getpass
import csv
import re

# ============================================================
# Files
# ============================================================

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

REPORT_FILE = f"dynamic_routes_{TIMESTAMP}.csv"
AUDIT_FILE = f"command_audit_{TIMESTAMP}.csv"
FAILED_FILE = f"failed_devices_{TIMESTAMP}.csv"

# ============================================================
# Globals
# ============================================================

COMMAND_LOG = []
FAILED_DEVICES = []

COMMAND_LOCK = Lock()
FAILED_LOCK = Lock()

DEVICE_TYPES = [
    "cisco_nxos",
    "cisco_xe",
    "cisco_ios",
    "arista_eos"
]

# ============================================================
# Device Detection
# ============================================================

def detect_device_type(host, username, password):

    print(f"[{host}] Detecting platform...")

    for device_type in DEVICE_TYPES:

        try:

            conn = ConnectHandler(
                device_type=device_type,
                host=host,
                username=username,
                password=password,
                fast_cli=False,
                banner_timeout=60,
                auth_timeout=60,
                conn_timeout=30
            )

            conn.disconnect()

            print(
                f"[{host}] Platform detected: "
                f"{device_type}"
            )

            return device_type

        except Exception:
            continue

    raise Exception(
        "Unable to determine device type"
    )

# ============================================================
# Command Execution
# ============================================================

def send_command(conn, host, command):

    with COMMAND_LOCK:
        COMMAND_LOG.append([
            host,
            command
        ])

    print(
        f"[{host}] Executing: "
        f"{command}"
    )

    output = conn.send_command(
        command,
        read_timeout=600
    )

    return output

# ============================================================
# Route Collection
# ============================================================

def get_route_table(conn, host, device_type):

    if device_type == "cisco_nxos":

        command = (
            "show ip route vrf all"
        )

    else:

        command = (
            "show ip route"
        )

    return send_command(
        conn,
        host,
        command
    )

# ============================================================
# Route Parsing
# ============================================================

def classify_protocol(route_text):

    lower = route_text.lower()

    if "bgp" in lower:
        return "BGP"

    if "ospf" in lower:
        return "OSPF"

    if "eigrp" in lower:
        return "EIGRP"

    return None


def parse_routes(route_output):

    routes = []

    current_vrf = "default"

    current_prefix = None

    lines = route_output.splitlines()

    for line in lines:

        line = line.rstrip()

        # ----------------------------------------------------
        # NXOS VRF Header
        # Example:
        # IP Route Table for VRF "PROD"
        # ----------------------------------------------------

        vrf_match = re.search(
            r'VRF\s+"?([^"]+)"?',
            line,
            re.I
        )

        if vrf_match:

            current_vrf = (
                vrf_match.group(1).strip()
            )

            continue

        # ----------------------------------------------------
        # Route Prefix
        # ----------------------------------------------------

        prefix_match = re.search(
            r'(\d+\.\d+\.\d+\.\d+\/\d+)',
            line
        )

        if prefix_match:

            current_prefix = (
                prefix_match.group(1)
            )

            protocol = classify_protocol(
                line
            )

            next_hop_match = re.search(
                r'via\s+(\d+\.\d+\.\d+\.\d+)',
                line,
                re.I
            )

            next_hop = (
                next_hop_match.group(1)
                if next_hop_match
                else ""
            )

            if protocol:

                routes.append([
                    current_vrf,
                    protocol,
                    current_prefix,
                    next_hop
                ])

            continue

        # ----------------------------------------------------
        # Multiline NXOS Route
        # ----------------------------------------------------

        if current_prefix:

            protocol = classify_protocol(
                line
            )

            if protocol:

                next_hop_match = re.search(
                    r'via\s+(\d+\.\d+\.\d+\.\d+)',
                    line,
                    re.I
                )

                next_hop = (
                    next_hop_match.group(1)
                    if next_hop_match
                    else ""
                )

                routes.append([
                    current_vrf,
                    protocol,
                    current_prefix,
                    next_hop
                ])

    # Deduplicate

    unique = []

    seen = set()

    for route in routes:

        key = tuple(route)

        if key not in seen:

            seen.add(key)

            unique.append(route)

    return unique

# ============================================================
# Device Processing
# ============================================================

def process_device(
        host,
        username,
        password):

    results = []

    try:

        print(
            f"[{host}] Connecting..."
        )

        device_type = detect_device_type(
            host,
            username,
            password
        )

        conn = ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            fast_cli=False,
            banner_timeout=60,
            auth_timeout=60,
            conn_timeout=30
        )

        print(
            f"[{host}] Connected "
            f"({device_type})"
        )

        route_output = get_route_table(
            conn,
            host,
            device_type
        )

        routes = parse_routes(
            route_output
        )

        print(
            f"[{host}] Found "
            f"{len(routes)} "
            f"dynamic routes"
        )

        for (
            vrf,
            protocol,
            subnet,
            next_hop
        ) in routes:

            results.append([
                host,
                device_type,
                vrf,
                protocol,
                subnet,
                next_hop
            ])

        conn.disconnect()

    except Exception as e:

        print(
            f"[{host}] FAILED: "
            f"{e}"
        )

        with FAILED_LOCK:

            FAILED_DEVICES.append([
                host,
                str(e)
            ])

    return results

# ============================================================
# Summary Display
# ============================================================

def display_summary(results):

    summary = {}

    for row in results:

        vrf = row[2]
        proto = row[3]
        subnet = row[4]

        summary.setdefault(
            vrf,
            {
                "BGP": set(),
                "OSPF": set(),
                "EIGRP": set()
            }
        )

        summary[vrf][proto].add(
            subnet
        )

    print()
    print("=" * 80)
    print("DYNAMIC ROUTE SUMMARY")
    print("=" * 80)

    for vrf in sorted(summary):

        print()
        print(
            f"VRF: {vrf}"
        )

        print("=" * 80)

        for proto in [
            "BGP",
            "OSPF",
            "EIGRP"
        ]:

            routes = sorted(
                summary[vrf][proto]
            )

            print()
            print(
                f"{proto} "
                f"({len(routes)} routes)"
            )

            print("-" * 80)

            for route in routes:

                print(route)

# ============================================================
# Report Writing
# ============================================================

def write_reports(results):

    with open(
        REPORT_FILE,
        "w",
        newline=""
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "Device",
            "Device Type",
            "VRF",
            "Protocol",
            "Subnet",
            "Next Hop"
        ])

        writer.writerows(results)

    with open(
        AUDIT_FILE,
        "w",
        newline=""
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "Device",
            "Command"
        ])

        writer.writerows(
            COMMAND_LOG
        )

    with open(
        FAILED_FILE,
        "w",
        newline=""
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "Device",
            "Error"
        ])

        writer.writerows(
            FAILED_DEVICES
        )

# ============================================================
# Main
# ============================================================

def main():

    start_time = datetime.now()

    hosts = input(
        "Hosts (comma delimited): "
    ).split(",")

    username = input(
        "Username: "
    )

    password = getpass.getpass(
        "Password: "
    )

    print()
    print("=" * 80)
    print("Dynamic Route Audit Tool")
    print("=" * 80)

    print(
        f"Devices Selected: "
        f"{len(hosts)}"
    )

    results = []

    with ThreadPoolExecutor(
        max_workers=5
    ) as pool:

        futures = {

            pool.submit(
                process_device,
                host.strip(),
                username,
                password
            ): host.strip()

            for host in hosts
        }

        for future in as_completed(
                futures):

            results.extend(
                future.result()
            )

    results.sort(
        key=lambda x: (
            x[0],
            x[2],
            x[3],
            x[4]
        )
    )

    display_summary(
        results
    )

    write_reports(
        results
    )

    runtime = (
        datetime.now()
        - start_time
    )

    print()
    print("=" * 80)
    print("PROCESSING COMPLETE")
    print("=" * 80)

    print(
        f"Routes Found     : "
        f"{len(results)}"
    )

    print(
        f"Failed Devices   : "
        f"{len(FAILED_DEVICES)}"
    )

    print(
        f"Runtime          : "
        f"{runtime}"
    )

    print()
    print("Generated Files:")

    print(
        f"  {REPORT_FILE}"
    )

    print(
        f"  {AUDIT_FILE}"
    )

    print(
        f"  {FAILED_FILE}"
    )


if __name__ == "__main__":
    main()