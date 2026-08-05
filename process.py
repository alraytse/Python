#!/usr/bin/env python3

import paramiko
import ipaddress
import getpass
import csv
import re
from concurrent.futures import ThreadPoolExecutor

USERNAME = ""
PASSWORD = ""

COMMAND_LOG = []

# =========================================================
# SSH
# =========================================================

def run_command(host, command):

    COMMAND_LOG.append([host, command])

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    ssh.connect(
        hostname=host,
        username=USERNAME,
        password=PASSWORD,
        timeout=30,
        look_for_keys=False,
        allow_agent=False
    )

    stdin, stdout, stderr = ssh.exec_command(
        command
    )

    output = stdout.read().decode(
        "utf-8",
        errors="ignore"
    )

    ssh.close()

    return output

# =========================================================
# DEVICE TYPE DETECTION
# =========================================================

def get_device_type(host):

    output = run_command(
        host,
        "show version"
    )

    if "Arista" in output:
        return "ARISTA"

    if "Nexus" in output:
        return "NXOS"

    return "IOS"

# =========================================================
# ARP FUNCTIONS
# =========================================================

def get_subnet_arp_count(
        arp_output,
        subnet):

    count = 0

    network = ipaddress.ip_network(
        subnet,
        strict=False
    )

    for line in arp_output.splitlines():

        match = re.search(
            r'(\d+\.\d+\.\d+\.\d+)',
            line
        )

        if not match:
            continue

        try:

            arp_ip = ipaddress.ip_address(
                match.group(1)
            )

            if arp_ip in network:
                count += 1

        except:
            pass

    return count


def get_utilization(
        subnet,
        arp_count):

    try:

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

    except:
        return 0

# =========================================================
# INTERFACE PARSING
# =========================================================

def parse_interfaces(config):

    interfaces = []

    blocks = re.findall(
        r'interface\s+(\S+)(.*?)(?=\ninterface\s+\S+|\Z)',
        config,
        re.S
    )

    for intf, block in blocks:

        description = ""

        desc_match = re.search(
            r'description\s+(.+)',
            block
        )

        if desc_match:
            description = desc_match.group(1).strip()

        interfaces.append({
            "interface": intf,
            "description": description
        })

    return interfaces

# =========================================================
# VLAN DATABASE
# =========================================================

def build_vlan_db(config):

    vlan_db = {}

    vlan_blocks = re.findall(
        r'vlan\s+(\d+)(.*?)(?=\nvlan\s+\d+|\Z)',
        config,
        re.S | re.I
    )

    for vlan_id, block in vlan_blocks:

        vlan_name = ""

        match = re.search(
            r'name\s+(.+)',
            block,
            re.I
        )

        if match:
            vlan_name = match.group(1).strip()

        vlan_db[f"Vlan{vlan_id}"] = vlan_name

    return vlan_db

# =========================================================
# VLAN LOOKUP
# =========================================================

def get_vlan_info(
        interface_name,
        vlan_db):

    if not interface_name:
        return "", ""

    match = re.search(
        r'Vlan(\d+)',
        interface_name,
        re.I
    )

    if not match:
        return "", ""

    vlan_id = match.group(1)

    vlan_name = vlan_db.get(
        f"Vlan{vlan_id}",
        ""
    )

    return vlan_id, vlan_name

# =========================================================
# LLDP / CDP PARSING
# =========================================================

def parse_neighbors(output):

    neighbors = {}

    for line in output.splitlines():

        fields = line.split()

        if len(fields) >= 2:

            neighbors[
                fields[0]
            ] = fields[-1]

    return neighbors

# =========================================================
# ROUTE LOOKUP
# =========================================================

def get_route_info(host, subnet):

    route_ip = str(
        ipaddress.ip_network(
            subnet,
            strict=False
        ).network_address
    )

    output = run_command(
        host,
        f"show ip route {route_ip}"
    )

    route_type = "Unknown"

    output_lower = output.lower()

    if "ospf" in output_lower:
        route_type = "OSPF"

    elif "bgp" in output_lower:
        route_type = "BGP"

    elif "eigrp" in output_lower:
        route_type = "EIGRP"

    elif "isis" in output_lower:
        route_type = "ISIS"

    elif "static" in output_lower:
        route_type = "Static"

    connected_match = re.search(
        r'directly connected,\s*(\S+)',
        output,
        re.I
    )

    if connected_match:

        return {
            "route_type": "Connected",
            "interface": connected_match.group(1),
            "next_hop": ""
        }

    vlan_route_match = re.search(
        r'via\s+(\d+\.\d+\.\d+\.\d+).*?(Vlan\d+)',
        output,
        re.I | re.S
    )

    if vlan_route_match:

        return {
            "route_type": route_type,
            "interface": vlan_route_match.group(2),
            "next_hop": vlan_route_match.group(1)
        }

    generic_route_match = re.search(
        r'via\s+(\d+\.\d+\.\d+\.\d+)',
        output,
        re.I
    )

    if generic_route_match:

        return {
            "route_type": route_type,
            "interface": "",
            "next_hop": generic_route_match.group(1)
        }

    return {
        "route_type": "Unknown",
        "interface": "",
        "next_hop": ""
    }

# =========================================================
# USAGE DESCRIPTION
# =========================================================

def determine_usage(
        route_info,
        interfaces,
        vlan_db):

    vlan_id, vlan_name = get_vlan_info(
        route_info["interface"],
        vlan_db
    )

    if vlan_name:

        return (
            f"{vlan_name} "
            f"(VLAN {vlan_id})"
        )

    for interface in interfaces:

        if (
            interface["interface"]
            == route_info["interface"]
        ):

            if interface["description"]:
                return interface["description"]

    if route_info["next_hop"]:

        return (
            f"Routed via "
            f"{route_info['next_hop']}"
        )

    return "Unknown"

# =========================================================
# PROCESS DEVICE
# =========================================================

def process_device(host, subnets):

    results = []

    host = host.strip()

    try:

        print("\n" + "=" * 80)
        print(f"Processing Device : {host}")
        print("=" * 80)

        device_type = get_device_type(host)

        print(
            f"Device Type       : {device_type}"
        )

        arp_cmd = "show ip arp"

        if device_type == "NXOS":
            arp_cmd = "show ip arp vrf all"

        print("Collecting ARP table...")

        arp_output = run_command(
            host,
            arp_cmd
        )

        try:

            print("Collecting LLDP neighbors...")

            neighbor_output = run_command(
                host,
                "show lldp neighbors"
            )

        except:

            print(
                "LLDP unavailable, trying CDP..."
            )

            neighbor_output = run_command(
                host,
                "show cdp neighbors"
            )

        print(
            "Collecting running configuration..."
        )

        running_config = run_command(
            host,
            "show running-config"
        )

        interfaces = parse_interfaces(
            running_config
        )

        vlan_db = build_vlan_db(
            running_config
        )

        neighbors = parse_neighbors(
            neighbor_output
        )

        print(
            f"Interfaces Found : {len(interfaces)}"
        )

        print(
            f"VLANs Found      : {len(vlan_db)}"
        )

        for subnet in subnets:

            print("\n" + "-" * 80)
            print(
                f"Checking Subnet  : {subnet}"
            )

            route_info = get_route_info(
                host,
                subnet
            )

            arp_count = get_subnet_arp_count(
                arp_output,
                subnet
            )

            utilization = get_utilization(
                subnet,
                arp_count
            )

            vlan_id, vlan_name = get_vlan_info(
                route_info["interface"],
                vlan_db
            )

            usage = determine_usage(
                route_info,
                interfaces,
                vlan_db
            )

            neighbor = neighbors.get(
                route_info["interface"],
                ""
            )

            print(
                f"Route Type       : "
                f"{route_info['route_type']}"
            )

            if route_info["interface"]:

                print(
                    f"Interface        : "
                    f"{route_info['interface']}"
                )

            if route_info["next_hop"]:

                print(
                    f"Next Hop         : "
                    f"{route_info['next_hop']}"
                )

            if vlan_id:

                print(
                    f"VLAN ID          : {vlan_id}"
                )

                print(
                    f"VLAN Name        : {vlan_name}"
                )

            if neighbor:

                print(
                    f"Neighbor Device  : {neighbor}"
                )

            print(
                f"ARP Count        : {arp_count}"
            )

            print(
                f"ARP Utilization  : "
                f"{utilization}%"
            )

            results.append([

                subnet,
                host,
                device_type,
                route_info["route_type"],
                route_info["interface"],
                vlan_id,
                vlan_name,
                usage,
                neighbor,
                arp_count,
                utilization

            ])

    except Exception as e:

        print(
            f"{host} failed: {e}"
        )

    return results

# =========================================================
# MAIN
# =========================================================

def main():

    global USERNAME
    global PASSWORD

    hosts = input(
        "Enter comma-delimited hostnames: "
    ).split(",")

    starting_subnet = input(
        "Enter starting subnet: "
    ).strip()

    mask = input(
        "Enter subnet mask length: "
    ).strip()

    subnet_count = int(
        input(
            "Number of subnets to check: "
        )
    )

    USERNAME = input(
        "Username: "
    )

    PASSWORD = getpass.getpass(
        "Password: "
    )

    base_network = ipaddress.ip_network(
        f"{starting_subnet}/{mask}",
        strict=False
    )

    subnets = []

    current = base_network.network_address

    for _ in range(subnet_count):

        network = ipaddress.ip_network(
            f"{current}/{mask}",
            strict=False
        )

        subnets.append(
            str(network)
        )

        current += network.num_addresses

    results = []

    with ThreadPoolExecutor(
        max_workers=20
    ) as executor:

        futures = [

            executor.submit(
                process_device,
                host.strip(),
                subnets
            )

            for host in hosts
        ]

        for future in futures:

            results.extend(
                future.result()
            )

    print("\n" + "=" * 80)
    print("PROCESSING SUMMARY")
    print("=" * 80)
    print(
        f"Total Records Generated: "
        f"{len(results)}"
    )

    with open(
            "subnet_report.csv",
            "w",
            newline=""
    ) as csvfile:

        writer = csv.writer(
            csvfile
        )

        writer.writerow([
            "IP Subnet",
            "Device",
            "Device Type",
            "Route Type",
            "Interface",
            "VLAN ID",
            "VLAN Name",
            "Usage in Plain Language",
            "Other Devices Connected",
            "# ARPs",
            "ARP Utilization %"
        ])

        writer.writerows(results)

    with open(
            "command_audit.csv",
            "w",
            newline=""
    ) as csvfile:

        writer = csv.writer(
            csvfile
        )

        writer.writerow([
            "Device",
            "Command"
        ])

        writer.writerows(
            COMMAND_LOG
        )

    print("\nGenerated Files:")
    print("  subnet_report.csv")
    print("  command_audit.csv")


if __name__ == "__main__":
    main()