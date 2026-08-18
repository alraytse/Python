#!/usr/bin/env python3

from netmiko import ConnectHandler
import getpass
import csv
import re
from datetime import datetime

OUTPUT_FILE = (
    f"circuit_inventory_"
    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
)

###############################################################################
# VENDOR DETECTION
###############################################################################

VENDOR_PATTERNS = {
    "Verizon": [
        r"verizon",
        r"\bvrt\b",
        r"\bvzw\b",
        r"alter\.net",
        r"uunet",
    ],
    "AT&T": [
        r"att",
        r"at&t",
    ],
    "Lumen": [
        r"lumen",
        r"centurylink",
        r"\bctl\b",
    ],
    "Cogent": [
        r"cogent",
    ],
    "Comcast": [
        r"comcast",
    ],
    "Zayo": [
        r"zayo",
    ],
}


def detect_vendor(text):

    text = text.lower()

    for vendor, patterns in VENDOR_PATTERNS.items():

        for pattern in patterns:

            if re.search(pattern, text, re.IGNORECASE):
                return vendor

    return "Unknown"


###############################################################################
# CIRCUIT ID EXTRACTION
###############################################################################

CIRCUIT_PATTERNS = [
    r"\bCKT[- ]?[A-Z0-9\-]+\b",
    r"\bCID[- ]?[A-Z0-9\-]+\b",
    r"\bCIRCUIT[- ]?[A-Z0-9\-]+\b",
    r"\bVZ[- ]?[A-Z0-9\-]+\b",
    r"\bATT[- ]?[A-Z0-9\-]+\b",
    r"\bCTL[- ]?[A-Z0-9\-]+\b",
    r"\bCOGENT[- ]?[A-Z0-9\-]+\b",
    r"\b[A-Z]{2,8}-[A-Z0-9]{3,30}\b",
    r"\b\d{8,20}\b",
]


def extract_circuit_ids(text):

    ids = set()

    for pattern in CIRCUIT_PATTERNS:

        matches = re.findall(
            pattern,
            text,
            re.IGNORECASE,
        )

        ids.update(matches)

    return ",".join(sorted(ids))


###############################################################################
# KEYWORD DETECTION
###############################################################################

def get_keywords(text):

    keywords = []

    text = text.lower()

    if "internet" in text:
        keywords.append("INTERNET")

    if "isp" in text:
        keywords.append("ISP")

    if "fw" in text:
        keywords.append("FW")

    if "firewall" in text:
        keywords.append("FW")

    if "verizon" in text:
        keywords.append("VERIZON")

    if "vrt" in text:
        keywords.append("VERIZON")

    if "vpn" in text:
        keywords.append("VPN")

    return ",".join(sorted(set(keywords)))


###############################################################################
# CIRCUIT TYPE
###############################################################################

def determine_circuit_type(text):

    text = text.lower()

    if "verizon" in text:
        return "Internet"

    if "internet" in text:
        return "Internet"

    if "isp" in text:
        return "Internet"

    if "fw" in text:
        return "Firewall"

    if "firewall" in text:
        return "Firewall"

    if "vpn" in text:
        return "VPN"

    return "Unknown"


###############################################################################
# NOTES
###############################################################################

def build_notes(
    interface_status,
    vendor,
    circuit_ids,
):

    notes = []

    if interface_status.lower() not in [
        "connected",
        "up",
    ]:
        notes.append("Interface Down")

    if vendor == "Unknown":
        notes.append("Vendor Unknown")

    if not circuit_ids:
        notes.append("Circuit ID Missing")

    return "; ".join(notes)


###############################################################################
# GET INTERFACE DESCRIPTIONS
###############################################################################

def get_descriptions(output):

    descriptions = {}

    for line in output.splitlines():

        cols = line.split()

        if len(cols) < 4:
            continue

        interface = cols[0]

        description = " ".join(cols[3:])

        descriptions[interface] = description

    return descriptions


###############################################################################
# GET CDP NEIGHBORS
###############################################################################

def get_neighbors(output):

    neighbors = {}

    neighbor = ""

    for line in output.splitlines():

        if "Device ID:" in line:

            neighbor = line.split(
                "Device ID:"
            )[1].strip()

        if "Interface:" in line:

            match = re.search(
                r"Interface:\s*([^,]+)",
                line,
            )

            if match:

                local_int = match.group(1).strip()

                neighbors[local_int] = neighbor

    return neighbors


###############################################################################
# PROCESS DEVICE
###############################################################################

def process_device(
    hostname,
    username,
    password,
):

    results = []

    device = {
        "device_type": "cisco_nxos",
        "host": hostname,
        "username": username,
        "password": password,
    }

    try:

        conn = ConnectHandler(**device)

        print(f"[+] Connected to {hostname}")

        status_output = conn.send_command(
            "show interface status"
        )

        desc_output = conn.send_command(
            "show interface description"
        )

        cdp_output = conn.send_command(
            "show cdp neighbors detail"
        )

        desc_map = get_descriptions(
            desc_output
        )

        neighbor_map = get_neighbors(
            cdp_output
        )

        for line in status_output.splitlines():

            if not line.startswith("Eth"):
                continue

            cols = line.split()

            if len(cols) < 3:
                continue

            interface = cols[0]

            interface_status = cols[2]

            vlan = ""

            if len(cols) >= 4:
                vlan = cols[3]

            description = desc_map.get(
                interface,
                ""
            )

            neighbor = neighbor_map.get(
                interface,
                ""
            )

            search_text = (
                description
                + " "
                + neighbor
            )

            vendor = detect_vendor(
                search_text
            )

            circuit_ids = extract_circuit_ids(
                search_text
            )

            keywords = get_keywords(
                search_text
            )

            circuit_type = determine_circuit_type(
                search_text
            )

            notes = build_notes(
                interface_status,
                vendor,
                circuit_ids,
            )

            results.append([
                hostname,
                hostname,
                interface,
                interface_status,
                "",
                "",
                vlan,
                "",
                "",
                "",
                vendor,
                circuit_ids,
                circuit_type,
                "YES",
                keywords,
                description,
                notes,
            ])

        conn.disconnect()

    except Exception as exc:

        print(
            f"[ERROR] {hostname}: {exc}"
        )

    return results


###############################################################################
# MAIN
###############################################################################

def main():

    hosts = input(
        "Switches (comma separated): "
    )

    username = input(
        "Username: "
    )

    password = getpass.getpass(
        "Password: "
    )

    all_results = []

    for host in hosts.split(","):

        host = host.strip()

        if not host:
            continue

        all_results.extend(
            process_device(
                host,
                username,
                password,
            )
        )

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8",
    ) as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
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
        ])

        writer.writerows(
            all_results
        )

    print()
    print("=" * 60)
    print("Circuit Inventory Complete")
    print("=" * 60)
    print(f"Output File : {OUTPUT_FILE}")
    print(f"Records     : {len(all_results)}")
    print("=" * 60)


if __name__ == "__main__":
    main()