#!/usr/bin/env python3

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import getpass
import io
import re
import sys
from pathlib import Path
from urllib.request import Request, urlopen

from netmiko import ConnectHandler

CSV_FILE = "stp_vlan_report.csv"
MAC_OID_BASE = "1.3.6.1.2.1.17.4.3.1.1"
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"

DEFAULT_MAX_MAC_COUNT = 2
DEFAULT_MAX_ARP_COUNT = 2
DEFAULT_WORKERS = 5

TRAFFIC_NOT_CONFIRMED = {
    "TRAFFIC_UNAVAILABLE",
    "NOT_CHECKED",
    "NO_ACCESS_PORTS",
}


def parse_vlans(output):
    vlan_map = {}

    for line in output.splitlines():
        match = re.match(r"^(\d+)\s+(\S+)", line.strip())
        if match:
            vlan_id = match.group(1)
            vlan_map[vlan_id] = {
                "vlan": vlan_id,
                "name": match.group(2),
            }

    return list(vlan_map.values())


def normalize_mac(mac):
    hex_digits = re.sub(r"[^0-9a-fA-F]", "", mac)

    if len(hex_digits) != 12:
        raise ValueError(f"Invalid MAC address: {mac}")

    return [
        int(hex_digits[i:i + 2], 16)
        for i in range(0, 12, 2)
    ]


def format_mac(mac, output_format="cisco"):
    octets = normalize_mac(mac)
    value = "".join(f"{octet:02x}" for octet in octets)

    if output_format == "colon":
        return ":".join(
            value[i:i + 2]
            for i in range(0, 12, 2)
        )

    if output_format == "hyphen":
        return "-".join(
            value[i:i + 2]
            for i in range(0, 12, 2)
        )

    return ".".join(
        value[i:i + 4]
        for i in range(0, 12, 4)
    )


def mac_to_oid(mac, base_oid=MAC_OID_BASE):
    octets = normalize_mac(mac)
    base_parts = [int(x) for x in base_oid.strip(".").split(".")]

    return ".".join(
        str(v)
        for v in (base_parts + octets)
    )


def parse_mac_table(output):
    entries = []

    mac_pattern = (
        r"^\s*\*?\s*(\d+)\s+"
        r"([0-9a-fA-F]{4}(?:[.:-][0-9a-fA-F]{4}){2}|"
        r"[0-9a-fA-F]{12})\b"
    )

    for line in output.splitlines():

        match = re.match(mac_pattern, line)

        is_dynamic = re.search(
            r"\bdynamic\b",
            line,
            re.IGNORECASE
        )

        port_match = re.search(
            r"\b((?:Eth(?:ernet)?|Po(?:rt-channel)?|"
            r"port-channel|sup-eth|mgmt)\S*)\s*$",
            line,
            re.IGNORECASE,
        )

        if match and is_dynamic:
            entries.append(
                {
                    "vlan": match.group(1),
                    "mac": format_mac(match.group(2)),
                    "port": port_match.group(1)
                    if port_match else "",
                }
            )

    return entries


def build_vlan_mac_map(mac_entries):

    vlan_map = {}

    for entry in mac_entries:
        vlan = entry["vlan"]
        vlan_map.setdefault(vlan, []).append(entry)

    return vlan_map


def parse_arp_table(output):

    mac_pattern = (
        r"[0-9a-fA-F]{4}(?:[.:-][0-9a-fA-F]{4}){2}|"
        r"[0-9a-fA-F]{12}"
    )

    vlan_pattern = r"\b[Vv]lan\s*(\d+)\b"

    arp_entries = {}

    for line in output.splitlines():

        mac_match = re.search(mac_pattern, line)
        vlan_match = re.search(vlan_pattern, line)

        if mac_match and vlan_match:

            vlan = vlan_match.group(1)
            mac = format_mac(mac_match.group(0))

            arp_entries.setdefault(vlan, set()).add(mac)

    return arp_entries


def get_arp_table(connection):

    try:
        output = connection.send_command(
            "show ip arp",
            read_timeout=30
        )

        return parse_arp_table(output), True

    except Exception as error:
        print(f"ARP lookup failed: {error}")
        return {}, False


def get_hostname(connection):
    prompt = connection.find_prompt()
    return prompt.replace("#", "").replace(">", "").strip()


def normalize_assignment(value):
    value = re.sub(r"[^0-9a-fA-F]", "", value)
    return value[:6].upper() if len(value) >= 6 else ""


def read_oui_csv(csv_text):

    reader = csv.DictReader(io.StringIO(csv_text))

    assignment_field = next(
        (
            f for f in reader.fieldnames
            if f.strip().lower() == "assignment"
        ),
        None,
    )

    organization_field = next(
        (
            f for f in reader.fieldnames
            if f.strip().lower() in
            {"organization name", "organization"}
        ),
        None,
    )

    organizations = {}

    for row in reader:

        assignment = normalize_assignment(
            row.get(assignment_field, "")
        )

        organization = row.get(
            organization_field,
            ""
        ).strip()

        if assignment and organization:
            organizations[assignment] = organization

    return organizations


def load_oui_registry(oui_file=None, offline=False):

    if oui_file:
        return read_oui_csv(
            Path(oui_file).read_text(
                encoding="utf-8"
            )
        )

    if offline:
        return {}

    request = Request(
        IEEE_OUI_URL,
        headers={
            "User-Agent": "stp-vlan-report/1.0"
        },
    )

    with urlopen(request, timeout=20) as response:
        csv_text = response.read().decode(
            "utf-8-sig"
        )

    return read_oui_csv(csv_text)


def decode_mac(mac, base_oid, oui_registry):

    octets = normalize_mac(mac)

    oui = "".join(
        f"{o:02X}"
        for o in octets[:3]
    )

    formatted_oui = (
        f"{oui[:2]}-{oui[2:4]}-{oui[4:6]}"
    )

    oid = mac_to_oid(mac, base_oid)

    first_octet = octets[0]

    if first_octet & 0x01:
        company = "Multicast address"

    elif first_octet & 0x02:
        company = (
            "Locally administered/randomized MAC"
        )

    else:
        company = oui_registry.get(
            oui,
            "Not found in IEEE registry",
        )

    return formatted_oui, oid, company


def get_mac_info(
    vlan,
    vlan_mac_map,
    base_oid,
    oui_registry,
):

    entries = vlan_mac_map.get(str(vlan), [])

    mac_addresses = []
    mac_companies = []
    mac_ports = []

    for entry in entries:

        mac = entry["mac"]

        _, _, company = decode_mac(
            mac,
            base_oid,
            oui_registry,
        )

        mac_addresses.append(mac)
        mac_companies.append(company)

        if entry["port"]:
            mac_ports.append(entry["port"])

    return {
        "MAC_Count": str(len(mac_addresses)),
        "MAC_Address": "; ".join(mac_addresses),
        "MAC_Company": "; ".join(mac_companies),
        "MAC_Port": "; ".join(
            dict.fromkeys(mac_ports)
        ),
    }


def parse_interface_rate(output, direction):

    pattern = re.compile(
        rf"(?:5 minute|30 seconds)\s+{direction}put rate\s+"
        r"([0-9,]+)\s+bits/sec",
        re.IGNORECASE,
    )

    rates = []

    for match in pattern.finditer(output):
        rates.append(
            int(match.group(1).replace(",", ""))
        )

    return max(rates, default=None)


def check_port_traffic(connection, port_list):

    ports = [
        p.strip()
        for p in port_list.split(";")
        if p.strip()
    ]

    if not ports:
        return "NO_ACCESS_PORTS", ""

    checked_ports = []
    successful_checks = 0
    traffic_detected = False

    for port in dict.fromkeys(ports):

        try:

            output = connection.send_command(
                f"show interface {port}",
                read_timeout=30,
            )

            in_rate = parse_interface_rate(
                output,
                "in"
            )

            out_rate = parse_interface_rate(
                output,
                "out"
            )

            if in_rate is None and out_rate is None:
                continue

            successful_checks += 1

            checked_ports.append(port)

            if (
                (in_rate or 0) > 0
                or (out_rate or 0) > 0
            ):
                traffic_detected = True

        except Exception:
            continue

    if traffic_detected:
        return "TRAFFIC_DETECTED", "; ".join(checked_ports)

    if successful_checks:
        return "NO_TRAFFIC", "; ".join(checked_ports)

    return "TRAFFIC_UNAVAILABLE", "; ".join(checked_ports)


def check_root(connection, vlan):

    try:
        output = connection.send_command(
            f"show spanning-tree vlan {vlan}",
            read_timeout=30,
        )

        return "This bridge is the root" in output

    except Exception:
        return False


def get_arp_count(arp_entries, vlan):
    return len(arp_entries.get(str(vlan), set()))


def get_svi_info(connection, vlan,
                 base_oid,
                 oui_registry):

    description = ""
    ip_address = ""
    svi_mac = ""
    svi_company = ""

    try:

        output = connection.send_command(
            f"show run interface vlan {vlan}",
            read_timeout=30,
        )

        for line in output.splitlines():

            line = line.strip()

            if line.startswith("description "):
                description = line.replace(
                    "description ",
                    "",
                    1
                )

            elif line.startswith("ip address "):
                ip_address = line.replace(
                    "ip address ",
                    "",
                    1
                )

    except Exception:
        pass

    try:

        output = connection.send_command(
            f"show interface vlan {vlan}",
            read_timeout=30,
        )

        match = re.search(
            r"address is\s+([0-9a-fA-F.:-]+)",
            output,
            re.IGNORECASE,
        )

        if match:

            svi_mac = format_mac(match.group(1))

            _, _, svi_company = decode_mac(
                svi_mac,
                base_oid,
                oui_registry,
            )

    except Exception:
        pass

    return (
        description,
        ip_address,
        svi_mac,
        svi_company,
    )


def get_shutdown_recommendation(
    mac_count,
    arp_count,
    traffic_check,
    is_root,
):

    if is_root:
        return (
            "NONE",
            "STP root bridge"
        )

    if mac_count == 0 and arp_count == 0:

        if traffic_check == "NO_TRAFFIC":
            return (
                "STRONG",
                "No MACs, ARPs, or traffic",
            )

        return (
            "MODERATE",
            "No MACs or ARPs; traffic not confirmed",
        )

    if mac_count == 0 or arp_count == 0:

        return (
            "WEAK",
            "Only one endpoint source empty",
        )

    return (
        "NONE",
        "MAC and ARP entries present",
    )


def process_switch(
    device,
    base_oid,
    oui_registry,
    max_mac_count,
    max_arp_count,
):

    results = []
    connection = None

    try:

        print(
            f"\nConnecting to {device['host']}..."
        )

        connection = ConnectHandler(**device)

        hostname = get_hostname(connection)

        vlan_output = connection.send_command(
            "show vlan brief",
            read_timeout=30,
        )

        vlans = parse_vlans(vlan_output)

        mac_output = connection.send_command(
            "show mac address-table",
            read_timeout=60,
        )

        vlan_mac_map = build_vlan_mac_map(
            parse_mac_table(mac_output)
        )

        arp_entries, arp_available = (
            get_arp_table(connection)
        )

        print(
            f"{hostname}: Found {len(vlans)} VLANs"
        )

        for vlan_info in vlans:

            vlan_id = vlan_info["vlan"]

            mac_info = get_mac_info(
                vlan_id,
                vlan_mac_map,
                base_oid,
                oui_registry,
            )

            mac_count = int(
                mac_info["MAC_Count"]
            )

            arp_count = get_arp_count(
                arp_entries,
                vlan_id,
            )

            if not arp_available:
                continue

            if (
                mac_count > max_mac_count
                or arp_count > max_arp_count
            ):
                continue

            traffic_check = "NOT_CHECKED"
            traffic_ports = ""

            if (
                1 <= mac_count <= max_mac_count
                or
                1 <= arp_count <= max_arp_count
            ):
                traffic_check, traffic_ports = (
                    check_port_traffic(
                        connection,
                        mac_info["MAC_Port"],
                    )
                )

            svi_description, svi_ip, \
                svi_mac, svi_company = (
                    get_svi_info(
                        connection,
                        vlan_id,
                        base_oid,
                        oui_registry,
                    )
                )

            is_root = check_root(
                connection,
                vlan_id
            )

            recommend, reason = (
                get_shutdown_recommendation(
                    mac_count,
                    arp_count,
                    traffic_check,
                    is_root,
                )
            )

            results.append(
                {
                    "Device": hostname,
                    "VLAN": vlan_id,
                    "VLAN_Name": vlan_info["name"],
                    "SVI_IP": svi_ip,
                    "SVI_MAC": svi_mac,
                    "SVI_MAC_Company": svi_company,
                    "SVI_Description": svi_description,
                    "MAC_Count": str(mac_count),
                    "ARP_Count": str(arp_count),
                    "Traffic_Check": traffic_check,
                    "Traffic_Ports": traffic_ports,
                    "MAC_Address": mac_info["MAC_Address"],
                    "MAC_Company": mac_info["MAC_Company"],
                    "Root_Bridge": (
                        "YES"
                        if is_root
                        else "NO"
                    ),
                    "Shutdown_Recommendation": recommend,
                    "Shutdown_Recommendation_Reason": reason,
                }
            )

    except Exception as error:

        print(
            f"Failed connection to "
            f"{device['host']} : {error}"
        )

    finally:

        if connection:
            connection.disconnect()

    return results


def write_csv(results, filename):

    if not results:
        return

    fields = results[0].keys()

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8",
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fields,
        )

        writer.writeheader()
        writer.writerows(results)


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--csv-file",
        default=CSV_FILE,
    )

    parser.add_argument(
        "--max-mac-count",
        type=int,
        default=DEFAULT_MAX_MAC_COUNT,
    )

    parser.add_argument(
        "--max-arp-count",
        type=int,
        default=DEFAULT_MAX_ARP_COUNT,
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
    )

    parser.add_argument(
        "--offline",
        action="store_true",
    )

    parser.add_argument(
        "--oui-file",
    )

    args = parser.parse_args()

    hosts = input(
        "Enter switch hostnames/IPs (comma delimited): "
    )

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    oui_registry = load_oui_registry(
        args.oui_file,
        args.offline,
    )

    devices = []

    for host in hosts.split(","):

        host = host.strip()

        if host:

            devices.append(
                {
                    "device_type": "cisco_nxos",
                    "host": host,
                    "username": username,
                    "password": password,
                    "fast_cli": False,
                }
            )

    all_results = []

    with ThreadPoolExecutor(
        max_workers=min(
            args.workers,
            len(devices)
        )
    ) as executor:

        futures = [
            executor.submit(
                process_switch,
                device,
                MAC_OID_BASE,
                oui_registry,
                args.max_mac_count,
                args.max_arp_count,
            )
            for device in devices
        ]

        for future in as_completed(futures):
            all_results.extend(
                future.result()
            )

    all_results.sort(
        key=lambda x:
        (
            x["Device"],
            int(x["VLAN"])
        )
    )

    write_csv(
        all_results,
        args.csv_file,
    )

    print(
        f"\nCSV report saved to: "
        f"{args.csv_file}"
    )


if __name__ == "__main__":
    sys.exit(main())