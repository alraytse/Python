
#!/usr/bin/env python3

import argparse
import csv
import getpass
import ipaddress
import re
import sys
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

DEFAULT_OUTPUT = "azure_local_dhcp_networks.csv"
DEFAULT_RAW_DIR = "infoblox_raw_output"
DEFAULT_TIMEOUT = 60

IP_RE = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
CIDR_RE = rf"\b{IP_RE}/\d{{1,2}}\b"

OUTPUT_FIELDS = [
    "Site Code",
    "IP Range",
    "Gateway",
    "DHCP Range",
    "Network Name or Comment",
    "Network View",
    "Infoblox Device",
    "Notes",
]

def valid_ipv4(value):
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False

def parse_ipv4(value):
    return ipaddress.ip_address(value)

def normalize_space(value):
    return re.sub(r"\s+", " ", value or "").strip()

def extract_cidr(text):
    match = re.search(CIDR_RE, text, re.IGNORECASE)

    if not match:
        return ""

    cidr = match.group(0)

    try:
        return str(ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        return ""

def network_blocks(output):
    """Split show network output into blocks keyed by network CIDR."""
    blocks = []
    current = None

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        cidr = extract_cidr(line)

        if cidr:
            if current is not None:
                blocks.append(current)

            current = {
                "cidr": cidr,
                "text": line,
            }
            continue

        if current is not None:
            current["text"] += "\n" + line

    if current is not None:
        blocks.append(current)

    return blocks

def unique_networks(blocks):
    """Deduplicate networks while retaining their combined text."""
    combined = {}

    for block in blocks:
        cidr = block["cidr"]

        if cidr not in combined:
            combined[cidr] = {
                "cidr": cidr,
                "text": block["text"],
            }
        else:
            combined[cidr]["text"] += "\n" + block["text"]

    return list(combined.values())

def extract_network_label(text):
    patterns = [
        r"(?:network\s+name|name|comment|description)\s*[:=]\s*([^\n]+)",
        r"(?:network\s+name|comment|description)\s+([^\n]+)",
    ]

    labels = []

    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            label = normalize_space(match.group(1))
            label = re.sub(
                r"\s+Network\s+View\s*[:=].*$",
                "",
                label,
                flags=re.IGNORECASE,
            )

            if label and label not in labels:
                labels.append(label)

    if labels:
        return "; ".join(labels)

    useful_lines = []

    for line in text.splitlines():
        line = normalize_space(line)

        if not line:
            continue

        if re.search(CIDR_RE, line, re.IGNORECASE):
            continue

        if re.search(
            r"azure\s+local|uson|idrac|comment|description|network\s+name",
            line,
            re.IGNORECASE,
        ):
            useful_lines.append(line)

    return "; ".join(useful_lines[:3])

def extract_network_view(text):
    match = re.search(
        r"(?:network\s+view|network_view)\s*[:=]\s*([^\s,;]+)",
        text,
        re.IGNORECASE,
    )

    return match.group(1).strip() if match else ""

def extract_site_code(text, custom_pattern=""):
    if custom_pattern:
        try:
            match = re.search(custom_pattern, text, re.IGNORECASE)

            if match:
                return (
                    match.group(1).strip()
                    if match.lastindex
                    else match.group(0).strip()
                )

        except re.error as exc:
            raise ValueError(
                f"Invalid site-code regex: {exc}"
            ) from exc

    labeled_patterns = [
        r"site\s*code\s*[:=]\s*([A-Za-z0-9_-]+)",
        r"site\s*[:=]\s*([A-Za-z0-9_-]+)",
    ]

    for pattern in labeled_patterns:
        match = re.search(pattern, text, re.IGNORECASE)

        if match:
            return match.group(1).strip()

    code_matches = re.findall(
        r"\b[A-Z]{2,8}\d{1,3}\b",
        text.upper(),
    )

    for code in code_matches:
        if code != "USON":
            return code

    match = re.search(
        r"\bUSON[-_ ]([A-Z0-9][A-Z0-9_-]*)",
        text,
        re.IGNORECASE,
    )

    if match:
        return match.group(1).strip("-_ ")

    return "UNKNOWN"

def text_matches(text, match_text, require_uson=False):
    normalized = normalize_space(text).lower()

    if match_text.lower() not in normalized:
        return False

    if require_uson and "uson" not in normalized:
        return False

    return "idrac" not in normalized

def extract_gateway(text):
    patterns = [
        rf"(?:default\s+gateway|gateway|routers?|router)\s*[:=]?\s*({IP_RE})",
        rf"({IP_RE})\s*(?:\([^)]*\))?\s*(?:default\s+gateway|gateway|router)\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)

        if match and valid_ipv4(match.group(1)):
            return match.group(1)

    return ""

def extract_ip_pairs(text):
    """Extract likely DHCP start/end pairs from range output lines."""
    pairs = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        addresses = [
            address
            for address in re.findall(IP_RE, line)
            if valid_ipv4(address)
        ]

        if len(addresses) < 2:
            continue

        has_range_context = bool(
            re.search(
                r"range|start|end|to|[-–—]",
                line,
                re.IGNORECASE,
            )
        )

        if not has_range_context:
            continue

        for index in range(len(addresses) - 1):
            start = addresses[index]
            end = addresses[index + 1]

            try:
                if parse_ipv4(start) <= parse_ipv4(end):
                    pair = (start, end)

                    if pair not in pairs:
                        pairs.append(pair)

            except ValueError:
                continue

    return pairs

def find_dhcp_ranges(range_output, network_cidr, network_detail=""):
    """Return DHCP ranges whose endpoints are inside the target network."""
    target_network = ipaddress.ip_network(
        network_cidr,
        strict=False,
    )

    pairs = extract_ip_pairs(range_output)
    pairs.extend(extract_ip_pairs(network_detail))

    matching = []
    seen = set()

    for start, end in pairs:
        start_ip = parse_ipv4(start)
        end_ip = parse_ipv4(end)

        if start_ip not in target_network:
            continue

        if end_ip not in target_network:
            continue

        range_value = f"{start}-{end}"

        if range_value not in seen:
            matching.append(range_value)
            seen.add(range_value)

    return matching

def get_command(connection, command, timeout):
    return connection.send_command(
        command,
        read_timeout=timeout,
        strip_prompt=True,
        strip_command=True,
    )

def write_raw_output(raw_dir, hostname, command_name, output):
    safe_host = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        hostname,
    )

    safe_command = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        command_name,
    )

    path = raw_dir / f"{safe_host}_{safe_command}.txt"
    path.write_text(
        output or "",
        encoding="utf-8",
    )

def collect_device(
    host,
    username,
    password,
    match_text,
    require_uson,
    site_code_pattern,
    network_command,
    range_command,
    timeout,
    raw_dir,
):
    connection = None
    results = []

    try:
        connection = ConnectHandler(
            device_type="infoblox_nios",
            host=host,
            username=username,
            password=password,
            fast_cli=False,
            global_delay_factor=2,
        )

        hostname = connection.find_prompt().strip()
        hostname = hostname.rstrip("#>").strip()
        hostname = hostname or host

        network_output = get_command(
            connection,
            network_command,
            timeout,
        )

        range_output = get_command(
            connection,
            range_command,
            timeout,
        )

        write_raw_output(
            raw_dir,
            hostname,
            "show_network",
            network_output,
        )

        write_raw_output(
            raw_dir,
            hostname,
            "show_range",
            range_output,
        )

        blocks = unique_networks(
            network_blocks(network_output)
        )

        if not blocks:
            print(
                f"{hostname}: no CIDR networks parsed; "
                "raw output saved.",
                file=sys.stderr,
            )
            return results

        for block in blocks:
            cidr = block["cidr"]
            summary_text = block["text"]

            try:
                detail_output = get_command(
                    connection,
                    f"show network {cidr}",
                    timeout,
                )

            except Exception as exc:
                detail_output = (
                    f"Detail query failed: {exc}"
                )

            combined_text = (
                f"{summary_text}\n{detail_output}"
            )

            if not text_matches(
                combined_text,
                match_text,
                require_uson,
            ):
                continue

            gateway = extract_gateway(combined_text)

            dhcp_ranges = find_dhcp_ranges(
                range_output,
                cidr,
                detail_output,
            )

            if not dhcp_ranges:
                continue

            notes = []

            if not gateway:
                notes.append(
                    "Gateway not found in Infoblox output"
                )

            results.append(
                {
                    "Site Code": extract_site_code(
                        combined_text,
                        site_code_pattern,
                    ),
                    "IP Range": cidr,
                    "Gateway": gateway,
                    "DHCP Range": "; ".join(dhcp_ranges),
                    "Network Name or Comment": (
                        extract_network_label(combined_text)
                    ),
                    "Network View": extract_network_view(
                        combined_text
                    ),
                    "Infoblox Device": hostname,
                    "Notes": "; ".join(notes),
                }
            )

    except NetmikoAuthenticationException:
        print(
            f"{host}: authentication failure.",
            file=sys.stderr,
        )

    except NetmikoTimeoutException:
        print(
            f"{host}: connection timeout.",
            file=sys.stderr,
        )

    except Exception as exc:
        print(
            f"{host}: collection failure: {exc}",
            file=sys.stderr,
        )

    finally:
        if connection is not None:
            connection.disconnect()

    return results

def write_csv(rows, filename):
    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8",
    ) as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=OUTPUT_FIELDS,
        )

        writer.writeheader()
        writer.writerows(rows)

def main():
    parser = argparse.ArgumentParser(
        description=(
            "SSH to Infoblox NIOS, filter Azure Local DHCP "
            "networks, and report site code, network, gateway, "
            "and DHCP range."
        )
    )

    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
        help=(
            f"CSV output file; default: {DEFAULT_OUTPUT}"
        ),
    )

    parser.add_argument(
        "--match",
        default="Azure Local",
        help=(
            "text required in the network name or comment; "
            'default: "Azure Local"'
        ),
    )

    parser.add_argument(
        "--require-uson",
        action="store_true",
        help=(
            "also require USON in the network name, "
            "comment, or detail"
        ),
    )

    parser.add_argument(
        "--site-code-regex",
        default="",
        help=(
            "optional regex for site code; use capture "
            "group 1 when present"
        ),
    )

    parser.add_argument(
        "--network-command",
        default="show network",
        help="Infoblox command listing networks",
    )

    parser.add_argument(
        "--range-command",
        default="show range",
        help="Infoblox command listing DHCP ranges",
    )

    parser.add_argument(
        "--raw-dir",
        default=DEFAULT_RAW_DIR,
        help=(
            f"directory for raw Infoblox output; "
            f"default: {DEFAULT_RAW_DIR}"
        ),
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=(
            f"command read timeout in seconds; "
            f"default: {DEFAULT_TIMEOUT}"
        ),
    )

    args = parser.parse_args()

    hosts_input = input(
        "Infoblox hostname/IP(s), comma delimited: "
    ).strip()

    hosts = [
        host.strip()
        for host in hosts_input.split(",")
        if host.strip()
    ]

    if not hosts:
        print(
            "No Infoblox hostnames or IP addresses were provided."
        )
        sys.exit(1)

    username = input("Infoblox user ID: ").strip()
    password = getpass.getpass("Infoblox password: ")

    raw_dir = Path(args.raw_dir)
    raw_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    all_rows = []

    for host in hosts:
        all_rows.extend(
            collect_device(
                host=host,
                username=username,
                password=password,
                match_text=args.match,
                require_uson=args.require_uson,
                site_code_pattern=args.site_code_regex,
                network_command=args.network_command,
                range_command=args.range_command,
                timeout=args.timeout,
                raw_dir=raw_dir,
            )
        )

    all_rows.sort(
        key=lambda row: (
            row["Site Code"],
            row["IP Range"],
        )
    )

    write_csv(
        all_rows,
        args.output,
    )

    print(f"\nMatching DHCP networks: {len(all_rows)}")
    print(f"CSV report: {args.output}")
    print(f"Raw command output: {raw_dir}")

if __name__ == "__main__":
    main()
