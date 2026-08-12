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

SEARCH_KEYWORDS = [
    "LUMEN",
    "CENTURYLINK",
    "CLINK",
    "METRO",
    "METRO-E",
    "ATT",
    "AT&T",
    "VERIZON",
    "MPLS",
    "INTERNET",
    "ISP",
    "UPLINK",
    "WAN",
    "FIREWALL",
    "FW",
    "F5",
    "LB",
    "SLB",
]

OUTPUT_FILE = (
    f"circuit_inventory_"
    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
)


def normalize_status(status, protocol):

    status = status.lower()
    protocol = protocol.lower()

    if status == "up" and protocol == "up":
        return "up"

    return "down"


def determine_vendor(description):

    desc = description.upper()

    if "VERIZON" in desc:
        return "Verizon"

    if any(
        x in desc for x in
        [
            "LUMEN",
            "CENTURYLINK",
            "CLINK",
            "METRO-E"
        ]
    ):
        return "CenturyLink/Lumen"

    if any(
        x in desc for x in
        [
            "ATT",
            "AT&T"
        ]
    ):
        return "AT&T"

    return ""


def determine_circuit_type(description):

    desc = description.upper()

    if "MPLS" in desc:
        return "MPLS"

    if (
        "METRO-E" in desc
        or "METROE" in desc
        or "METRO" in desc
    ):
        return "Metro-E"

    if (
        "INTERNET" in desc
        or "ISP" in desc
    ):
        return "Internet"

    if (
        "FW" in desc
        or "FIREWALL" in desc
    ):
        return "Firewall"

    if "F5" in desc:
        return "Load Balancer"

    return ""


def extract_circuit_ids(description):

    patterns = [
        r"\bCID[:\s#-]*([A-Z0-9\-]+)\b",
        r"\bCIRCUIT\s*ID[:\s#-]*([A-Z0-9\-]+)\b",
        r"\bCKT[:\[A-Z0-s#-]*([A-Z0-9\-]+)\b",
  r"\bCKT#\s*([A-Z0-9\-]+)\b",
        r"\b(U\d{4,})\b",
        r"\b(ATT[-_][A-Z0-9]+)\b",
        r"\b(VZ[-_][A-Z0-9]+)\b",
        r"\b(CLINK[-_][A-Z0-9]+)\b",
        r"\b([A-Z]{2,6}\d{5,15})\b",
    ]

    results = set()

    for pattern in patterns:

        matches = re.findall(
            pattern,
            description,
            re.IGNORECASE
        )

        for match in matches:
            results.add(match)

    return ",".join(sorted(results))


def determine_directly_attached(description):

    patterns = [
        r"(DDC1-[A-Z0-9_-]+)",
        r"(DDC-[A-Z0-9_-]+)",
        r"(USON-[A-Z0-9_-]+)",
        r"(FW[0-9]+)",
        r"(GW[0-9]+)",
        r"(ASW[0-9]+)",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            description,
            re.IGNORECASE
        )

        if match:
            return match.group(1)

    return ""


def parse_interface_descriptions(output):

    interfaces = []

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.lower().startswith("interface"):
            continue

        if "----" in line:
            continue

        parts = re.split(
            r"\s{2,}",
            line,
            maxsplit=3
        )

        if len(parts) < 4:
            continue

        interfaces.append(
            {
                "interface": parts[0],
                "admin_status": parts[1],
                "oper_status": parts[2],
                "status": normalize_status(
                    parts[1],
                    parts[2]
                ),
                "description": parts[3],
            }
        )

    return interfaces


def parse_vlan_info(output):

    vlan_map = {}

    current_intf = None

    for line in output.splitlines():

        line = line.strip()

        m = re.match(
            r"Name:\s+(\S+)",
            line,
            re.IGNORECASE,
        )

        if m:
            current_intf = m.group(1)

            vlan_map[current_intf] = {
                "vlan": "",
                "mode": "",
                "native_vlan": "",
                "allowed_vlans": "",
            }

            continue

        if not current_intf:
            continue

        access_match = re.search(
            r"Access Mode VLAN:\s+(\d+)",
            line,
            re.IGNORECASE,
        )

        if access_match:
            vlan_map[current_intf]["vlan"] = (
                access_match.group(1)
            )

        op_mode = re.search(
            r"Operational Mode:\s+(.+)",
            line,
            re.IGNORECASE,
        )

        if op_mode:
            mode = op_mode.group(1)

            vlan_map[current_intf]["mode"] = mode

            if "trunk" in mode.lower():
                vlan_map[current_intf]["vlan"] = "Trunk"

        native_match = re.search(
            r"Trunking Native Mode VLAN:\s+(\d+)",
            line,
            re.IGNORECASE,
        )

        if native_match:
            vlan_map[current_intf]["native_vlan"] = (
                native_match.group(1)
            )

    return vlan_map


def build_notes(record):

    notes = []

    if record["Interface Status"] == "down":
        notes.append("Interface Down")

    if not record["Circuit Vendor"]:
        notes.append("Vendor Unknown")

    if not record["Circuit IDs"]:
        notes.append("Circuit ID Missing")

    return "; ".join(notes)


def find_matches(output):

    interfaces = parse_interface_descriptions(
        output
    )

    results = []

    for interface in interfaces:

        desc_upper = (
            interface["description"]
            .upper()
        )

        matched = []

        for keyword in SEARCH_KEYWORDS:
            if keyword in desc_upper:
                matched.append(keyword)

        if matched:

            results.append(
                {
                    "Interface":
                        interface["interface"],
                    "Admin Status":
                        interface["admin_status"],
                    "Operational Status":
                        interface["oper_status"],
                    "Interface Status":
                        interface["status"],
                    "Description":
                        interface["description"],
                    "Matched Keywords":
                        ",".join(
                            sorted(set(matched))
                        ),
                }
            )

    return results


def connect_to_device(
    host,
    username,
    password,
):

    device_types = [
        "cisco_nxos",
        "cisco_ios",
    ]

    for device_type in device_types:

        try:

            print(
                f"[INFO] {host} "
                f"({device_type})"
            )

            conn = ConnectHandler(
                device_type=device_type,
                host=host,
                username=username,
                password=password,
                fast_cli=False,
            )

            hostname = (
                conn.find_prompt()
                .rstrip("#>")
            )

            desc_output = conn.send_command(
                "show interface description",
                read_timeout=120,
            )

            try:

                vlan_output = (
                    conn.send_command(
                        "show interface switchport",
                        read_timeout=300,
                    )
                )

            except Exception:

                vlan_output = ""

            conn.disconnect()

            vlan_map = parse_vlan_info(
                vlan_output
            )

            records = []

            for match in find_matches(
                desc_output
            ):

                interface = (
                    match["Interface"]
                )

                vlan_data = vlan_map.get(
                    interface,
                    {}
                )

                record = {
                    "Device": hostname,
                    "Management IP": host,
                    "Interface": interface,
                    "Interface Status":
                        match["Interface Status"],
                    "Admin Status":
                        match["Admin Status"],
                    "Operational Status":
                        match["Operational Status"],
                    "VLAN":
                        vlan_data.get(
                            "vlan",
                            ""
                        ),
                    "Mode":
                        vlan_data.get(
                            "mode",
                            ""
                        ),
                    "Native VLAN":
                        vlan_data.get(
                            "native_vlan",
                            ""
                        ),
                    "Allowed VLANs":
                        vlan_data.get(
                            "allowed_vlans",
                            ""
                        ),
                    "Circuit Vendor":
                        determine_vendor(
                            match["Description"]
                        ),
                    "Circuit IDs":
                        extract_circuit_ids(
                            match["Description"]
                        ),
                    "Circuit Type":
                        determine_circuit_type(
                            match["Description"]
                        ),
                    "Circuit Directly Attached":
                        determine_directly_attached(
                            match["Description"]
                        ),
                    "Matched Keywords":
                        match["Matched Keywords"],
                    "Description":
                        match["Description"],
                }

                record["Notes"] = (
                    build_notes(record)
                )

                records.append(record)

            return records

        except Exception:
            continue

    raise Exception(
        f"Unable to connect to {host}"
    )


def write_csv(records):

    fields = [
        "Device",
        "Management IP",
        "Interface",
        "Interface Status",
        "Admin Status",
        "Operational Status",
        "VLAN",
        "Mode",
        "Native VLAN",
        "Allowed VLANs",
        "Circuit Vendor",
        "Circuit IDs",
        "Circuit Type",
        "Circuit Directly Attached",
        "Matched Keywords",
        "Description",
        "Notes",
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8",
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fields,
        )

        writer.writeheader()
        writer.writerows(records)

    print(
        f"\nCSV Written: "
        f"{OUTPUT_FILE}"
    )

    print(
        f"Records: "
        f"{len(records)}"
    )


def main():

    print(
        "\nCircuit Discovery Tool"
    )

    hosts_input = input(
        "\nHosts (comma separated): "
    ).strip()

    hosts = [
        h.strip()
        for h in hosts_input.split(",")
        if h.strip()
    ]

    username = input(
        "Username: "
    ).strip()

    password = getpass.getpass(
        "Password: "
    )

    all_records = []

    for host in hosts:

        try:

            all_records.extend(
                connect_to_device(
                    host,
                    username,
                    password,
                )
            )

        except (
            NetmikoAuthenticationException
        ):
            print(
                f"[ERROR] Auth failed "
                f"{host}"
            )

        except (
            NetmikoTimeoutException
        ):
            print(
                f"[ERROR] Timeout "
                f"{host}"
            )

        except Exception as exc:
            print(
                f"[ERROR] {host}: "
                f"{exc}"
            )

    write_csv(all_records)

    print("\nCompleted.")


if __name__ == "__main__":
    main()
