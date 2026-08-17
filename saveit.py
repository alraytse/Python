#!/usr/bin/env python3

import csv
import getpass
import ipaddress
import re
from datetime import datetime

from netmiko import ConnectHandler

OUTPUT_FILE = f"decom_candidates_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"


def get_subnets():
    print("\n=== Subnet Range Input ===")

    start_subnet = input("Starting Subnet: ").strip()
    end_subnet = input("Ending Subnet: ").strip()

    start_net = ipaddress.ip_network(start_subnet, strict=False)
    end_net = ipaddress.ip_network(end_subnet, strict=False)

    if start_net.prefixlen != end_net.prefixlen:
        raise ValueError(
            "Starting and Ending subnets must use the same mask."
        )

    subnets = []

    current = int(start_net.network_address)
    ending = int(end_net.network_address)

    increment = start_net.num_addresses

    while current <= ending:
        subnet = ipaddress.ip_network(
            (ipaddress.ip_address(current), start_net.prefixlen),
            strict=False
        )
        subnets.append(str(subnet))
        current += increment

    return subnets


def get_switches():
    value = input("Switches (comma separated): ").strip()
    return [x.strip() for x in value.split(",") if x.strip()]


def subnet_details(subnet):
    net = ipaddress.ip_network(subnet, strict=False)

    hosts = list(net.hosts())

    return {
        "Network": str(net.network_address),
        "Netmask": str(net.netmask),
        "Prefix": net.prefixlen,
        "FirstUsable": str(hosts[0]) if hosts else "",
        "LastUsable": str(hosts[-1]) if hosts else "",
        "UsableIPs": len(hosts),
    }


def get_route(conn, subnet):

    commands = [
        f"show ip route {subnet}",
        f"show route {subnet}",
    ]

    for cmd in commands:

        try:
            output = conn.send_command(cmd)

            if output:
                return output

        except Exception:
            pass

    return ""


def classify_route(route):

    route_lower = route.lower()

    if "null0" in route_lower:
        return "Null0"

    if "vlan" in route_lower:
        return "Connected"

    if "static" in route_lower:
        return "Static"

    if "bgp" in route_lower:
        return "BGP"

    return "Unknown"


def extract_vlan(route):

    match = re.search(r"vlan(\d+)", route, re.IGNORECASE)

    if match:
        return match.group(1)

    return ""


def extract_interface(route):

    patterns = [
        r"Vlan\d+",
        r"Ethernet\S+",
        r"Port-channel\S+",
        r"Loopback\d+",
    ]

    for pattern in patterns:
        match = re.search(pattern, route, re.IGNORECASE)

        if match:
            return match.group(0)

    return ""


def get_arp_count(conn, vlan):

    if not vlan:
        return 0

    try:
        output = conn.send_command(
            f"show ip arp vlan {vlan}",
            read_timeout=60
        )

    except Exception:
        return 0

    count = 0

    for line in output.splitlines():

        if "incomplete" in line.lower():
            continue

        if re.search(r"\d+\.\d+\.\d+\.\d+", line):
            count += 1

    return count


def get_mac_count(conn, vlan):

    if not vlan:
        return 0

    try:
        output = conn.send_command(
            f"show mac address-table vlan {vlan}",
            read_timeout=60
        )

    except Exception:
        return 0

    count = 0

    for line in output.splitlines():

        if re.search(
            r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}",
            line,
            re.IGNORECASE,
        ):
            count += 1

    return count


def get_bgp_status(conn, subnet):

    commands = [
        f"show ip bgp {subnet}",
        f"show bgp ipv4 unicast {subnet}",
    ]

    for cmd in commands:

        try:
            output = conn.send_command(cmd)

            if (
                output
                and "not in table" not in output.lower()
                and "network not in table" not in output.lower()
            ):
                return True

        except Exception:
            pass

    return False


def calculate_score(route_type,
                    arp_count,
                    mac_count,
                    bgp):

    score = 100

    if route_type != "Null0":
        score -= 30

    if arp_count > 0:
        score -= 20

    if mac_count > 0:
        score -= 20

    if bgp:
        score -= 30

    return max(score, 0)


def classify_candidate(route_type,
                       arp_count,
                       mac_count,
                       bgp):

    if (
        route_type == "Null0"
        and arp_count == 0
        and mac_count == 0
        and not bgp
    ):
        return "HIGH_CONFIDENCE_DECOM"

    if arp_count == 0 and mac_count == 0:
        return "REVIEW_REQUIRED"

    return "ACTIVE"


def main():

    subnets = get_subnets()

    switches = get_switches()

    username = input("Username: ").strip()

    password = getpass.getpass("Password: ")

    results = []

    for switch in switches:

        print(f"\nConnecting to {switch}...")

        device = {
            "device_type": "cisco_nxos",
            "host": switch,
            "username": username,
            "password": password,
        }

        try:
            conn = ConnectHandler(**device)

        except Exception as e:
            print(f"Failed connection to {switch}: {e}")
            continue

        for subnet in subnets:

            print(f"Checking {subnet}")

            route = get_route(conn, subnet)

            route_type = classify_route(route)

            vlan = extract_vlan(route)

            interface = extract_interface(route)

            arp_count = get_arp_count(conn, vlan)

            mac_count = get_mac_count(conn, vlan)

            bgp_present = get_bgp_status(conn, subnet)

            info = subnet_details(subnet)

            results.append({
                "Subnet": subnet,
                "Network": info["Network"],
                "Netmask": info["Netmask"],
                "Prefix": info["Prefix"],
                "FirstUsable": info["FirstUsable"],
                "LastUsable": info["LastUsable"],
                "UsableIPs": info["UsableIPs"],
                "Switch": switch,
                "Interface": interface,
                "VLAN": vlan,
                "RouteType": route_type,
                "ARP_Count": arp_count,
                "MAC_Count": mac_count,
                "BGP_Advertised": bgp_present,
                "Score": calculate_score(
                    route_type,
                    arp_count,
                    mac_count,
                    bgp_present
                ),
                "Status": classify_candidate(
                    route_type,
                    arp_count,
                    mac_count,
                    bgp_present
                ),
            })

        conn.disconnect()

    if results:

        with open(
            OUTPUT_FILE,
            "w",
            newline=""
        ) as csvfile:

            writer = csv.DictWriter(
                csvfile,
                fieldnames=list(results[0].keys())
            )

            writer.writeheader()
            writer.writerows(results)

        print(f"\nReport written to: {OUTPUT_FILE}")

    else:
        print("\nNo results generated.")


if __name__ == "__main__":
    main()