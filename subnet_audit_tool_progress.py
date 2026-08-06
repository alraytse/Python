#!/usr/bin/env python3

from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from datetime import datetime

import ipaddress
import getpass
import csv
import re

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

REPORT_FILE = f"subnet_report_{TIMESTAMP}.csv"
AUDIT_FILE = f"command_audit_{TIMESTAMP}.csv"
FAILED_FILE = f"failed_devices_{TIMESTAMP}.csv"

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
            pass

    raise Exception(
        "Unable to determine device type"
    )


def send_command(conn, host, command):

    with COMMAND_LOCK:

        COMMAND_LOG.append([
            host,
            command
        ])

    print(
        f"[{host}] Executing: {command}"
    )

    return conn.send_command(
        command,
        read_timeout=120
    )


def build_vlan_db(output):

    vlan_db = {}

    for line in output.splitlines():

        match = re.match(
            r"^\s*(\d+)\s+(\S+)",
            line
        )

        if match:

            vlan_db[
                f"Vlan{match.group(1)}"
            ] = match.group(2)

    return vlan_db


def get_vlan_info(interface_name, vlan_db):

    match = re.search(
        r"Vlan(\d+)",
        interface_name,
        re.I
    )

    if not match:

        match = re.search(
            r"\.(\d+)$",
            interface_name
        )

    if not match:

        return "", ""

    vlan_id = match.group(1)

    vlan_name = vlan_db.get(
        f"Vlan{vlan_id}",
        ""
    )

    return vlan_id, vlan_name


def get_arp_count(arp_output, subnet):

    network = ipaddress.ip_network(
        subnet,
        strict=False
    )

    unique_ips = set()

    for line in arp_output.splitlines():

        match = re.search(
            r"(\d+\.\d+\.\d+\.\d+)",
            line
        )

        if not match:
            continue

        try:

            ip = ipaddress.ip_address(
                match.group(1)
            )

            if ip in network:

                unique_ips.add(str(ip))

        except Exception:
            pass

    return len(unique_ips)


def get_utilization(subnet, arp_count):

    network = ipaddress.ip_network(
        subnet,
        strict=False
    )

    usable_hosts = max(
        network.num_addresses - 2,
        1
    )

    return round(
        (arp_count / usable_hosts) * 100,
        2
    )


def get_route_info(
        conn,
        host,
        subnet,
        device_type):

    network = ipaddress.ip_network(
        subnet,
        strict=False
    )

    if device_type == "cisco_nxos":

        command = (
            f"show ip route vrf all "
            f"{network.network_address}"
        )

    else:

        command = (
            f"show ip route "
            f"{network.network_address}"
        )

    output = send_command(
        conn,
        host,
        command
    )

    route_type = "Unknown"

    lower = output.lower()

    protocol_map = {
        "bgp": "BGP",
        "ospf": "OSPF",
        "eigrp": "EIGRP",
        "isis": "ISIS",
        "static": "Static",
        "connected": "Connected"
    }

    for keyword, proto in protocol_map.items():

        if keyword in lower:

            route_type = proto
            break

    next_hop = ""

    match = re.search(
        r"via\s+(\d+\.\d+\.\d+\.\d+)",
        output,
        re.I
    )

    if match:
        next_hop = match.group(1)

    interface = ""

    patterns = [

        r"(Vlan\d+)",
        r"(Loopback\d+)",
        r"(Port-channel\d+)",
        r"(Po\d+)",
        r"(GigabitEthernet\S+)",
        r"(TenGigabitEthernet\S+)",
        r"(TwentyFiveGigE\S+)",
        r"(FortyGigE\S+)",
        r"(HundredGigE\S+)",
        r"(TenGigE\S+)",
        r"(Ethernet\S+)",
        r"(Eth\S+)"
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            output,
            re.I
        )

        if match:

            interface = match.group(1)
            break

    return {
        "route_type": route_type,
        "interface": interface,
        "next_hop": next_hop
    }


def process_device(
        host,
        username,
        password,
        subnets):

    results = []

    try:

        print(f"[{host}] Connecting...")

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

        arp_cmd = (
            "show ip arp vrf all"
            if device_type == "cisco_nxos"
            else "show ip arp"
        )

        arp_output = send_command(
            conn,
            host,
            arp_cmd
        )

        vlan_output = send_command(
            conn,
            host,
            "show vlan brief"
        )

        vlan_db = build_vlan_db(
            vlan_output
        )

        for index, subnet in enumerate(
                subnets,
                start=1):

            print(
                f"[{host}] "
                f"Subnet "
                f"{index}/{len(subnets)} "
                f"{subnet}"
            )

            route = get_route_info(
                conn,
                host,
                subnet,
                device_type
            )

            print(
                f"[{host}] "
                f"{subnet} | "
                f"{route['route_type']} | "
                f"{route['interface']} | "
                f"Next-Hop={route['next_hop']}"
            )

            vlan_id, vlan_name = get_vlan_info(
                route["interface"],
                vlan_db
            )

            arp_count = get_arp_count(
                arp_output,
                subnet
            )

            utilization = get_utilization(
                subnet,
                arp_count
            )

            results.append([
                subnet,
                host,
                device_type,
                route["route_type"],
                route["interface"],
                vlan_id,
                vlan_name,
                route["next_hop"],
                arp_count,
                utilization
            ])

        print(
            f"[{host}] Finished "
            f"{len(subnets)} subnets"
        )

        conn.disconnect()

    except Exception as e:

        print(
            f"[{host}] FAILED: {e}"
        )

        with FAILED_LOCK:

            FAILED_DEVICES.append([
                host,
                str(e)
            ])

    return results


def main():

    start_time = datetime.now()

    hosts = input(
        "Hosts (comma delimited): "
    ).split(",")

    start = input(
        "Starting subnet: "
    ).strip()

    end = input(
        "Ending subnet: "
    ).strip()

    mask = input(
        "Mask Length: "
    ).strip()

    username = input(
        "Username: "
    )

    password = getpass.getpass(
        "Password: "
    )

    start_net = ipaddress.ip_network(
        f"{start}/{mask}",
        strict=False
    )

    end_net = ipaddress.ip_network(
        f"{end}/{mask}",
        strict=False
    )

    if end_net.network_address < start_net.network_address:

        raise ValueError(
            "Ending subnet must be greater than "
            "or equal to starting subnet"
        )

    subnets = []
    current = start_net.network_address

    while current <= end_net.network_address:

        network = ipaddress.ip_network(
            f"{current}/{mask}",
            strict=False
        )

        subnets.append(str(network))

        current += network.num_addresses

    print("\n" + "=" * 60)
    print("Subnet Audit Tool")
    print("=" * 60)

    print(f"Devices: {len(hosts)}")

    print(
        f"Subnet Range: "
        f"{start_net} -> {end_net}"
    )

    print(
        f"Total Subnets: "
        f"{len(subnets)}"
    )

    results = []

    with ThreadPoolExecutor(
            max_workers=5) as pool:

        futures = [

            pool.submit(
                process_device,
                host.strip(),
                username,
                password,
                subnets
            )

            for host in hosts
        ]

        for future in futures:

            results.extend(
                future.result()
            )

    results.sort(
        key=lambda x: (
            x[1],
            x[0]
        )
    )

    print("\nRoute Protocol Summary")
    print("=" * 60)

    protocols = {}

    for row in results:

        protocols.setdefault(
            row[3],
            set()
        ).add(
            row[0]
        )

    for protocol in sorted(protocols):

        print(f"\n{protocol}")

        for subnet in sorted(protocols[protocol]):

            print(
                f"  {subnet}"
            )

    with open(
            REPORT_FILE,
            "w",
            newline=""
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "IP Subnet",
            "Device",
            "Device Type",
            "Route Type",
            "Interface",
            "VLAN ID",
            "VLAN Name",
            "Next Hop",
            "# ARPs",
            "ARP Utilization %"
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

        writer.writerows(COMMAND_LOG)

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

        writer.writerows(FAILED_DEVICES)

    runtime = datetime.now() - start_time

    print("\n" + "=" * 60)
    print("Processing Complete")
    print("=" * 60)

    print(
        f"Records Generated : "
        f"{len(results)}"
    )

    print(
        f"Failed Devices    : "
        f"{len(FAILED_DEVICES)}"
    )

    print(
        f"Runtime           : "
        f"{runtime}"
    )

    print("\nGenerated Files:")

    print(f"  {REPORT_FILE}")
    print(f"  {AUDIT_FILE}")
    print(f"  {FAILED_FILE}")


if __name__ == "__main__":
    main()
    