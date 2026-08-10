#!/usr/bin/env python3

"""Global-table subnet audit for Cisco IOS/IOS-XE, NX-OS, and Arista EOS."""

import csv
import getpass
import ipaddress
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Lock

from netmiko import ConnectHandler


TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
REPORT_FILE = f"subnet_report_{TIMESTAMP}.csv"
LOG_FILE = f"subnet_audit_global_{TIMESTAMP}.log"
AUDIT_FILE = f"command_audit_{TIMESTAMP}.csv"
FAILED_FILE = f"failed_devices_{TIMESTAMP}.csv"

COMMAND_LOG = []
FAILED_DEVICES = []
COMMAND_LOCK = Lock()
FAILED_LOCK = Lock()

SUPPORTED_TYPES = {
    "cisco_ios",
    "cisco_xe",
    "cisco_nxos",
    "arista_eos",
}


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)


def record_command(host, command):
    with COMMAND_LOCK:
        COMMAND_LOG.append([datetime.now().isoformat(timespec="seconds"), host, command])


def send_command(conn, host, command, read_timeout=120):
    record_command(host, command)
    logging.info("%s: %s", host, command)
    return conn.send_command(command, read_timeout=read_timeout)



def configure_terminal(conn, host, device_type):
    try:
        command = "terminal length 0"
        if device_type == "arista_eos":
            command = "terminal length 0"
        send_command(conn, host, command, read_timeout=30)
    except Exception:
        logging.warning("%s: unable to disable terminal paging", host, exc_info=True)


def build_route_command(subnet, device_type):
    target = ipaddress.ip_network(subnet, strict=False).network_address
    return f"show ip route {target}"


def build_arp_command(device_type):
    return "show ip arp"


def build_ping_command(target, device_type):
    if device_type == "cisco_nxos":
        return f"ping {target} count 5 timeout 1"

    return f"ping {target} repeat 5 timeout 1"


def parse_ping_output(output):
    text = output.lower()

    match = re.search(r"success rate is\s+(\d+)\s*percent", text)
    if match:
        rate = int(match.group(1))
        sent = 5
        received = round(sent * rate / 100)
        return sent, received, rate, ping_status(rate)

    match = re.search(
        r"(\d+)\s+packets transmitted,\s*(\d+)\s+packets received",
        text,
    )
    if not match:
        match = re.search(
            r"(\d+)\s+packets transmitted,\s*(\d+)\s+received",
            text,
        )

    if match:
        sent = int(match.group(1))
        received = int(match.group(2))
        rate = round((received / sent) * 100) if sent else 0
        return sent, received, rate, ping_status(rate)

    match = re.search(r"(\d+)\s+packets received", text)
    if match:
        received = int(match.group(1))
        sent = 5
        rate = round((received / sent) * 100)
        return sent, received, rate, ping_status(rate)

    if "bytes from" in text or "reply from" in text:
        return 1, 1, 100, "REACHABLE"

    return 0, 0, 0, "PING_PARSE_ERROR"


def ping_status(rate):
    if rate == 100:
        return "REACHABLE"
    if rate > 0:
        return "PARTIAL"
    return "UNREACHABLE"


def parse_route_output(output):
    lower = output.lower()
    not_found_markers = (
        "network not in table",
        "subnet not in table",
        "route not found",
        "not found in routing table",
        "no route",
        "% invalid",
    )

    if any(marker in lower for marker in not_found_markers):
        return {
            "route_present": False,
            "route_type": "No Route",
            "interface": "",
            "next_hop": "",
        }

    route_present = bool(
        re.search(r"routing entry for|known via|is directly connected|via \d+\.\d+\.\d+\.\d+", lower)
    )

    route_type = "Unknown"
    protocol_patterns = [
        (r"\bis connected\b|directly connected", "Connected"),
        (r"\bstatic\b", "Static"),
        (r"\bbgp\b", "BGP"),
        (r"\bospf\b", "OSPF"),
        (r"\beigrp\b", "EIGRP"),
        (r"\bisis\b", "ISIS"),
    ]
    for pattern, name in protocol_patterns:
        if re.search(pattern, lower):
            route_type = name
            break

    next_hop_match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", output, re.I)
    next_hop = next_hop_match.group(1) if next_hop_match else ""

    interface = ""
    interface_patterns = [
        r"(Vlan\d+)",
        r"(Loopback\d+)",
        r"(Port-channel\d+)",
        r"(Port-Channel\d+)",
        r"(Po\d+)",
        r"(GigabitEthernet\S+)",
        r"(TenGigabitEthernet\S+)",
        r"(TwentyFiveGigE\S+)",
        r"(FortyGigE\S+)",
        r"(HundredGigE\S+)",
        r"(Ethernet\S+)",
        r"(Eth\S+)",
    ]
    for pattern in interface_patterns:
        match = re.search(pattern, output, re.I)
        if match:
            interface = match.group(1)
            break

    return {
        "route_present": route_present,
        "route_type": route_type if route_present else "No Route",
        "interface": interface,
        "next_hop": next_hop,
    }


def parse_vlan_name(output, vlan_id):
    for line in output.splitlines():
        match = re.match(rf"^\s*{re.escape(vlan_id)}\s+(\S+)", line)
        if match:
            return match.group(1)
    return ""


def get_vlan_info(conn, host, interface, device_type):
    match = re.search(r"Vlan(\d+)", interface or "", re.I)
    if not match:
        match = re.search(r"\.(\d+)$", interface or "")
    if not match:
        return "", ""

    vlan_id = match.group(1)
    try:
        output = send_command(conn, host, f"show vlan id {vlan_id}", read_timeout=60)
        return vlan_id, parse_vlan_name(output, vlan_id)
    except Exception:
        logging.warning("%s: VLAN lookup failed for %s", host, vlan_id, exc_info=True)
        return vlan_id, ""


def count_arp_entries(arp_output, subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    addresses = set()
    for ip in re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", arp_output):
        try:
            if ipaddress.ip_address(ip) in network:
                addresses.add(ip)
        except ValueError:
            continue
    return len(addresses)


def choose_ping_target(arp_output, subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    for ip in re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", arp_output):
        try:
            address = ipaddress.ip_address(ip)
            if address in network and address not in {network.network_address, network.broadcast_address}:
                return str(address)
        except ValueError:
            continue

    hosts = list(network.hosts())
    return str(hosts[0]) if hosts else str(network.network_address)


def process_device(host, username, password, device_type, subnets):
    results = []
    conn = None

    try:
        logging.info("%s: connecting with %s using the global routing table", host, device_type)
        conn = ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            fast_cli=False,
            banner_timeout=60,
            auth_timeout=60,
            conn_timeout=30,
        )
        configure_terminal(conn, host, device_type)

        arp_output = send_command(conn, host, build_arp_command(device_type))

        for subnet in subnets:
            route_command = build_route_command(subnet, device_type)
            try:
                route_output = send_command(conn, host, route_command)
                route = parse_route_output(route_output)
                collection_status = "OK"
                error = ""
            except Exception as exc:
                logging.exception("%s: route lookup failed for %s", host, subnet)
                route_output = ""
                route = {
                    "route_present": False,
                    "route_type": "Lookup Error",
                    "interface": "",
                    "next_hop": "",
                }
                collection_status = "ERROR"
                error = str(exc)

            vlan_id, vlan_name = get_vlan_info(
                conn, host, route["interface"], device_type
            ) if route["interface"] else ("", "")

            arp_count = count_arp_entries(arp_output, subnet)
            ping_target = choose_ping_target(arp_output, subnet)
            sent = received = success_rate = 0
            reachability = "NO_ROUTE"

            if collection_status == "ERROR":
                reachability = "ROUTE_LOOKUP_ERROR"
            elif not route["route_present"]:
                reachability = "ARP_ONLY" if arp_count else "NO_ROUTE"
            else:
                try:
                    ping_command = build_ping_command(ping_target, device_type)
                    ping_output = send_command(conn, host, ping_command, read_timeout=60)
                    sent, received, success_rate, reachability = parse_ping_output(ping_output)
                except Exception as exc:
                    logging.exception("%s: ping failed for %s", host, subnet)
                    reachability = "PING_ERROR"
                    error = str(exc)
                    collection_status = "ERROR"

            network = ipaddress.ip_network(subnet, strict=False)
            usable_hosts = max(network.num_addresses - 2, 1)
            utilization = round((arp_count / usable_hosts) * 100, 2)

            results.append([
                str(subnet),
                host,
                device_type,
                "YES" if route["route_present"] else "NO",
                route["route_type"],
                route["interface"],
                vlan_id,
                vlan_name,
                route["next_hop"],
                arp_count,
                utilization,
                ping_target,
                sent,
                received,
                success_rate,
                reachability,
                collection_status,
                error,
            ])

            logging.info(
                "%s: subnet=%s route=%s reachability=%s",
                host,
                subnet,
                route["route_type"],
                reachability,
            )

    except Exception as exc:
        logging.exception("%s: device processing failed", host)
        with FAILED_LOCK:
            FAILED_DEVICES.append([host, str(exc)])
    finally:
        if conn:
            try:
                conn.disconnect()
                logging.info("%s: disconnected", host)
            except Exception:
                logging.warning("%s: disconnect failed", host, exc_info=True)

    return results


def build_subnets(start_text, end_text):
    start_net = ipaddress.ip_network(start_text, strict=False)
    end_net = ipaddress.ip_network(end_text, strict=False)
    if start_net.prefixlen != end_net.prefixlen:
        raise ValueError("Starting and ending subnet must use the same prefix length")
    if end_net.network_address < start_net.network_address:
        raise ValueError("Ending subnet must be greater than or equal to starting subnet")

    subnets = []
    current = int(start_net.network_address)
    end = int(end_net.network_address)
    while current <= end:
        network = ipaddress.ip_network(
            f"{ipaddress.ip_address(current)}/{start_net.prefixlen}",
            strict=False,
        )
        subnets.append(str(network))
        current += network.num_addresses
    return subnets


def main():
    logging.info("Global-table subnet audit started")

    start_text = input("Starting subnet/mask: ").strip()
    end_text = input("Ending subnet/mask: ").strip()
    host_text = input("Hostnames/IPs (comma delimited): ").strip()
    device_type = input(
        "Device type [cisco_ios/cisco_xe/cisco_nxos/arista_eos] (default cisco_ios): "
    ).strip() or "cisco_ios"
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    if device_type not in SUPPORTED_TYPES:
        raise ValueError(f"Unsupported device type: {device_type}")

    hosts = [host.strip() for host in host_text.split(",") if host.strip()]
    if not hosts:
        raise ValueError("At least one host is required")

    subnets = build_subnets(start_text, end_text)
    logging.info(
        "Inputs: devices=%d subnets=%d device_type=%s",
        len(hosts), len(subnets), device_type,
    )

    results = []
    with ThreadPoolExecutor(max_workers=min(5, len(hosts))) as pool:
        futures = [
            pool.submit(process_device, host, username, password, device_type, subnets)
            for host in hosts
        ]
        for future in as_completed(futures):
            results.extend(future.result())

    results.sort(key=lambda row: (row[1], row[0]))

    with open(REPORT_FILE, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow([
            "IP Subnet", "Device", "Device Type", "Route Present",
            "Route Type", "Interface", "VLAN ID", "VLAN Name", "Next Hop",
            "ARP Count", "ARP Utilization %", "Ping Target", "ICMP Sent",
            "ICMP Received", "ICMP Success %", "Reachability Status",
            "Collection Status", "Error",
        ])
        writer.writerows(results)

    with open(AUDIT_FILE, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow(["Timestamp", "Device", "Command"])
        writer.writerows(COMMAND_LOG)

    with open(FAILED_FILE, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow(["Device", "Error"])
        writer.writerows(FAILED_DEVICES)

    logging.info("Report saved to %s", REPORT_FILE)
    logging.info("Audit saved to %s", AUDIT_FILE)
    logging.info("Failures saved to %s", FAILED_FILE)
    logging.info("Global-table subnet audit completed: %d records, %d failed devices", len(results), len(FAILED_DEVICES))


if __name__ == "__main__":
    main()
