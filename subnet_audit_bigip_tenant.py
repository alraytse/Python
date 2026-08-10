#!/usr/bin/env python3

"""Subnet audit for Cisco, Arista EOS, and BIG-IP tenant/partition contexts."""

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
LOG_FILE = f"subnet_audit_{TIMESTAMP}.log"
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
    "f5_tmsh",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)


def is_bigip(device_type):
    return device_type == "f5_tmsh"


def record_command(host, command):
    with COMMAND_LOCK:
        COMMAND_LOG.append([
            datetime.now().isoformat(timespec="seconds"),
            host,
            command,
        ])


def send_command(conn, host, command, read_timeout=120):
    record_command(host, command)
    logging.info("%s: %s", host, command)
    return conn.send_command(command, read_timeout=read_timeout)


def normalize_value(value):
    value = value.strip()
    return None if value.lower() in {"", "none", "default", "global"} else value


def configure_context(conn, host, device_type, tenant=None):
    if is_bigip(device_type):
        if tenant:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", tenant):
                raise ValueError("BIG-IP tenant/partition contains invalid characters")
            send_command(conn, host, f"cd /{tenant}", read_timeout=30)
            logging.info("%s: BIG-IP tenant context set to /%s", host, tenant)
        return

    try:
        send_command(conn, host, "terminal length 0", read_timeout=30)
    except Exception:
        logging.warning("%s: unable to disable terminal paging", host, exc_info=True)


def build_route_command(subnet, device_type, vrf=None):
    network = ipaddress.ip_network(subnet, strict=False)
    target = network.network_address

    if is_bigip(device_type):
        # BIG-IP tmsh route output is collected in the tenant partition context.
        # The parser selects the requested destination from the returned table.
        return "show net route"

    if vrf:
        return f"show ip route vrf {vrf} {target}"

    return f"show ip route {target}"


def build_arp_command(device_type, vrf=None):
    if is_bigip(device_type):
        return "show net arp"
    if vrf:
        return f"show ip arp vrf {vrf}"
    return "show ip arp"


def build_vlan_command(device_type):
    if is_bigip(device_type):
        # Recursive list returns VLAN names, tags, and partition-scoped objects.
        return "list net vlan recursive"
    return "show vlan brief"


def build_ping_command(target, device_type, vrf=None, route_domain_id=None):
    if is_bigip(device_type):
        scoped_target = target
        if route_domain_id and "%" not in scoped_target:
            scoped_target = f"{target}%{route_domain_id}"
        return f"run util ping -c 5 -W 1 {scoped_target}"

    if device_type == "cisco_nxos":
        command = f"ping {target} count 5 timeout 1"
        if vrf:
            command += f" vrf {vrf}"
        return command

    prefix = f"ping vrf {vrf} " if vrf else "ping "
    return f"{prefix}{target} repeat 5 timeout 1"


def ping_status(rate):
    if rate == 100:
        return "REACHABLE"
    if rate > 0:
        return "PARTIAL"
    return "UNREACHABLE"


def parse_ping_output(output):
    text = output.lower()

    match = re.search(r"success rate is\s+(\d+)\s*percent", text)
    if match:
        rate = int(match.group(1))
        sent = 5
        received = round(sent * rate / 100)
        return sent, received, rate, ping_status(rate)

    match = re.search(
        r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets )?received",
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


def parse_f5_vlan_db(output):
    """Return {short_vlan_name: {name, tag}} from tmsh VLAN configuration."""
    vlan_db = {}
    blocks = re.split(r"(?m)(?=^\s*(?:net\s+)?vlan\s+[^\s{]+\s*\{)", output)

    for block in blocks:
        name_match = re.search(
            r"(?m)^\s*(?:net\s+)?vlan\s+([^\s{]+)\s*\{",
            block,
        )
        if not name_match:
            continue

        full_name = name_match.group(1).strip("\"")
        short_name = full_name.rsplit("/", 1)[-1]
        tag_match = re.search(r"(?m)^\s*tag\s+(\d+)", block)
        tag = tag_match.group(1) if tag_match else ""
        vlan_db[short_name.lower()] = {
            "name": short_name,
            "full_name": full_name,
            "tag": tag,
        }

    return vlan_db


def parse_vlan_name(output, vlan_id):
    for line in output.splitlines():
        match = re.match(rf"^\s*{re.escape(vlan_id)}\s+(\S+)", line)
        if match:
            return match.group(1)
    return ""


def get_vlan_info(conn, host, interface, device_type, vlan_db=None):
    if not interface:
        return "", ""

    if is_bigip(device_type):
        short_name = interface.strip("/").rsplit("/", 1)[-1].lower()
        entry = (vlan_db or {}).get(short_name)
        if entry:
            return entry["tag"], entry["name"]
        return "", interface.strip("/").rsplit("/", 1)[-1]

    match = re.search(r"Vlan(\d+)", interface, re.IGNORECASE)
    if not match:
        match = re.search(r"\.(\d+)$", interface)
    if not match:
        return "", ""

    vlan_id = match.group(1)
    try:
        output = send_command(
            conn,
            host,
            f"show vlan id {vlan_id}",
            read_timeout=60,
        )
        return vlan_id, parse_vlan_name(output, vlan_id)
    except Exception:
        logging.warning("%s: VLAN lookup failed for %s", host, vlan_id, exc_info=True)
        return vlan_id, ""


def parse_route_output(output, subnet, device_type):
    lower = output.lower()
    network = ipaddress.ip_network(subnet, strict=False)
    destination = str(network)

    null_route = bool(re.search(
        r"\b(?:null\d*|discard|blackhole|reject)\b",
        output,
        re.IGNORECASE,
    ))

    if is_bigip(device_type):
        # tmsh output can contain many routes; require the requested destination.
        destination_present = destination in output or str(network.network_address) in output
        route_present = destination_present and not any(
            marker in lower for marker in ("not found", "no route", "error")
        )
    else:
        not_found_markers = (
            "network not in table",
            "subnet not in table",
            "route not found",
            "not found in routing table",
            "no route",
            "% invalid",
        )
        route_present = not any(marker in lower for marker in not_found_markers) and bool(
            re.search(
                r"routing entry for|known via|is directly connected|"
                r"via\s+(?:\d+\.\d+\.\d+\.\d+|null\d*|discard|blackhole|reject)",
                lower,
            )
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

    if null_route:
        route_type = "Null Route"
    elif not route_present:
        route_type = "No Route"

    next_hop_match = re.search(
        r"(?:via|gateway)\s+(\d+\.\d+\.\d+\.\d+)",
        output,
        re.IGNORECASE,
    )
    next_hop = next_hop_match.group(1) if next_hop_match else ""

    interface = ""
    interface_patterns = [
        r"(?:interface|dev|vlan)\s+(/?[A-Za-z0-9_.:/-]+)",
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
        r"(Null\d*)",
        r"(Discard|Blackhole|Reject)",
    ]
    for pattern in interface_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            interface = match.group(1)
            break

    return {
        "route_present": route_present,
        "null_route": null_route,
        "route_type": route_type,
        "interface": interface,
        "next_hop": next_hop,
    }


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
            if address in network and address not in {
                network.network_address,
                network.broadcast_address,
            }:
                return str(address)
        except ValueError:
            continue

    hosts = list(network.hosts())
    return str(hosts[0]) if hosts else str(network.network_address)


def process_device(
    host,
    username,
    password,
    device_type,
    vrf,
    tenant,
    route_domain_id,
    subnets,
):
    results = []
    conn = None

    try:
        context = tenant if is_bigip(device_type) else (vrf or "GLOBAL")
        logging.info("%s: connecting with %s context=%s", host, device_type, context)

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

        configure_context(conn, host, device_type, tenant)

        arp_output = send_command(
            conn,
            host,
            build_arp_command(device_type, vrf),
        )

        vlan_db = {}
        if is_bigip(device_type):
            vlan_output = send_command(
                conn,
                host,
                build_vlan_command(device_type),
            )
            vlan_db = parse_f5_vlan_db(vlan_output)

        for subnet in subnets:
            try:
                route_output = send_command(
                    conn,
                    host,
                    build_route_command(subnet, device_type, vrf),
                )
                route = parse_route_output(route_output, subnet, device_type)
                collection_status = "OK"
                error = ""
            except Exception as exc:
                logging.exception("%s: route lookup failed for %s", host, subnet)
                route = {
                    "route_present": False,
                    "null_route": False,
                    "route_type": "Lookup Error",
                    "interface": "",
                    "next_hop": "",
                }
                collection_status = "ERROR"
                error = str(exc)

            vlan_id, vlan_name = get_vlan_info(
                conn,
                host,
                route["interface"],
                device_type,
                vlan_db,
            )

            arp_count = count_arp_entries(arp_output, subnet)
            ping_target = choose_ping_target(arp_output, subnet)
            sent = received = success_rate = 0
            reachability = "NO_ROUTE"

            if collection_status == "ERROR":
                reachability = "ROUTE_LOOKUP_ERROR"
            elif route["null_route"]:
                reachability = "NULL_ROUTE"
            elif not route["route_present"]:
                reachability = "ARP_ONLY" if arp_count else "NO_ROUTE"
            else:
                try:
                    ping_output = send_command(
                        conn,
                        host,
                        build_ping_command(
                            ping_target,
                            device_type,
                            vrf,
                            route_domain_id,
                        ),
                        read_timeout=60,
                    )
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
                tenant or "",
                route_domain_id or "",
                vrf or "GLOBAL",
                "YES" if route["route_present"] else "NO",
                "YES" if route["null_route"] else "NO",
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

    if start_net.version != 4 or end_net.version != 4:
        raise ValueError("Only IPv4 subnets are supported")
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
    logging.info("Subnet audit started")

    start_text = input("Starting subnet/mask: ").strip()
    end_text = input("Ending subnet/mask: ").strip()
    host_text = input("Hostnames/IPs (comma delimited): ").strip()
    device_type = input(
        "Device type [cisco_ios/cisco_xe/cisco_nxos/arista_eos/f5_tmsh] "
        "(default cisco_ios): "
    ).strip() or "cisco_ios"

    tenant = None
    route_domain_id = None
    vrf = None

    if is_bigip(device_type):
        tenant = normalize_value(input("BIG-IP tenant/partition (blank for Common): "))
        route_domain_id = normalize_value(input("BIG-IP route-domain ID (optional): "))
        if route_domain_id and not route_domain_id.isdigit():
            raise ValueError("BIG-IP route-domain ID must be numeric")
    else:
        vrf = normalize_value(input("VRF (blank for global): "))

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    if device_type not in SUPPORTED_TYPES:
        raise ValueError(f"Unsupported device type: {device_type}")

    hosts = [host.strip() for host in host_text.split(",") if host.strip()]
    if not hosts:
        raise ValueError("At least one host is required")

    subnets = build_subnets(start_text, end_text)
    logging.info(
        "Inputs: devices=%d subnets=%d platform=%s tenant=%s route_domain=%s vrf=%s",
        len(hosts),
        len(subnets),
        device_type,
        tenant or "",
        route_domain_id or "",
        vrf or "GLOBAL",
    )

    results = []
    with ThreadPoolExecutor(max_workers=min(5, len(hosts))) as pool:
        futures = [
            pool.submit(
                process_device,
                host,
                username,
                password,
                device_type,
                vrf,
                tenant,
                route_domain_id,
                subnets,
            )
            for host in hosts
        ]
        for future in as_completed(futures):
            results.extend(future.result())

    results.sort(key=lambda row: (row[1], row[0]))

    with open(REPORT_FILE, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow([
            "IP Subnet",
            "Device",
            "Device Type",
            "BIG-IP Tenant/Partition",
            "BIG-IP Route Domain",
            "VRF",
            "Route Present",
            "Null Route",
            "Route Type",
            "Interface/VLAN",
            "VLAN ID/Tag",
            "VLAN Name",
            "Next Hop/Gateway",
            "ARP Count",
            "ARP Utilization %",
            "Ping Target",
            "ICMP Sent",
            "ICMP Received",
            "ICMP Success %",
            "Reachability Status",
            "Collection Status",
            "Error",
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
    logging.info(
        "Subnet audit completed: %d records, %d failed devices",
        len(results),
        len(FAILED_DEVICES),
    )


if __name__ == "__main__":
    main()
