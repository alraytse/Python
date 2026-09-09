#!/usr/bin/env python3
"""Collect Cisco ASA/FTD NAT rules over SSH and write a CSV report.

The script interactively prompts for:
  - one or more hostnames or management IPs
  - SSH user ID
  - SSH password
  - Netmiko device type
  - output CSV path

It is report-only: it runs show commands and never changes configuration.

Supported device type:
  cisco_asa

Install the dependency:
  python -m pip install netmiko
"""

from __future__ import annotations

import csv
import getpass
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


DEFAULT_WORKERS = 15


REPORT_COLUMNS = [
    "Device Name",
    "Management IP",
    "Vendor",
    "Model",
    "NAT Type",
    "Original Source Network",
    "Original Destination Network",
    "Translated Source",
    "Translated Destination",
    "Service/Port",
    "Interface In",
    "Interface Out",
    "Rule Name",
    "Rule ID",
    "Enabled/Disabled",
    "Comments",
]


@dataclass
class NetworkObject:
    name: str
    original: str = ""
    description: str = ""
    nat_lines: List[str] = field(default_factory=list)


@dataclass
class NatRule:
    original_source: str = ""
    original_destination: str = "Any"
    translated_source: str = ""
    translated_destination: str = "Any"
    service: str = "Any"
    interface_in: str = ""
    interface_out: str = ""
    rule_name: str = ""
    nat_type: str = ""
    comments: str = ""


def prompt_hosts() -> List[str]:
    raw = input("Enter hostname(s) or management IP(s), separated by commas: ").strip()
    hosts = [host.strip() for host in raw.split(",") if host.strip()]
    if not hosts:
        raise ValueError("At least one hostname or management IP is required.")
    return hosts


def prompt_device_type() -> str:
    device_type = input("Netmiko device type [cisco_asa]: ").strip() or "cisco_asa"
    if device_type != "cisco_asa":
        raise ValueError("This collector currently supports only the cisco_asa device type.")
    return device_type


def prompt_output_path() -> Path:
    raw = input("Output CSV path [nat_rule_report.csv]: ").strip()
    return Path(raw or "nat_rule_report.csv")


def send_command(connection, command: str) -> str:
    return connection.send_command(
        command,
        expect_string=None,
        strip_prompt=True,
        strip_command=True,
    ) or ""


def parse_model(version_output: str) -> str:
    for line in version_output.splitlines():
        match = re.search(r"\bHardware:\s*(.+)$", line, re.I)
        if match:
            return match.group(1).strip()
        match = re.search(r"\b(ASA\d+[A-Za-z0-9-]*)\b", line, re.I)
        if match:
            return match.group(1)
    return "Unknown"


def parse_network_objects(output: str) -> Dict[str, NetworkObject]:
    objects: Dict[str, NetworkObject] = {}
    current: Optional[NetworkObject] = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("!"):
            continue

        match = re.match(r"object network (\S+)$", line, re.I)
        if match:
            current = NetworkObject(name=match.group(1))
            objects[current.name] = current
            continue

        if current is None:
            continue

        match = re.match(r"description\s+(.+)$", line, re.I)
        if match:
            current.description = match.group(1).strip()
            continue

        match = re.match(r"host\s+(\S+)$", line, re.I)
        if match:
            current.original = match.group(1)
            continue

        match = re.match(r"subnet\s+(\S+)\s+(\S+)$", line, re.I)
        if match:
            current.original = f"{match.group(1)} {match.group(2)}"
            continue

        match = re.match(r"range\s+(\S+)\s+(\S+)$", line, re.I)
        if match:
            current.original = f"{match.group(1)}-{match.group(2)}"
            continue

        if re.match(r"nat\s+\(", line, re.I):
            current.nat_lines.append(line)

    return objects


def parse_interface_pair(text: str) -> Tuple[str, str]:
    match = re.match(r"\(([^,]+),([^\)]+)\)", text)
    if not match:
        return "", ""
    return match.group(1), match.group(2)


def nat_type_from_translation(translation: str, has_service: bool = False) -> str:
    lowered = translation.lower()
    if lowered.startswith("static"):
        return "Static NAT"
    if lowered.startswith("dynamic"):
        if "interface" in lowered or has_service:
            return "PAT"
        return "Dynamic NAT"
    return ""


def resolve_object(value: str, objects: Dict[str, NetworkObject]) -> str:
    obj = objects.get(value)
    if obj and obj.original:
        return obj.original
    return value


def parse_object_nat_rules(
    objects: Dict[str, NetworkObject],
) -> List[NatRule]:
    rules: List[NatRule] = []

    for object_name, obj in objects.items():
        for nat_line in obj.nat_lines:
            match = re.match(r"nat\s+(\([^\)]+\))\s+(.+)$", nat_line, re.I)
            if not match:
                continue

            interface_in, interface_out = parse_interface_pair(match.group(1))
            remainder = match.group(2).strip()
            tokens = remainder.split()
            if not tokens:
                continue

            translation = " ".join(tokens)
            is_service = " service " in f" {remainder.lower()} "
            rule = NatRule(
                original_source=obj.original or object_name,
                translated_source="",
                interface_in=interface_in,
                interface_out=interface_out,
                rule_name=object_name,
                nat_type=nat_type_from_translation(translation, is_service),
                comments=obj.description,
            )

            if tokens[0].lower() == "static" and len(tokens) >= 2:
                rule.translated_source = resolve_object(tokens[1], objects)
            elif tokens[0].lower() == "dynamic" and len(tokens) >= 2:
                rule.translated_source = (
                    "Outside Interface" if tokens[1].lower() == "interface" else resolve_object(tokens[1], objects)
                )
            else:
                continue

            service_index = next(
                (index for index, token in enumerate(tokens) if token.lower() == "service"),
                None,
            )
            if service_index is not None:
                service_tokens = tokens[service_index + 1 :]
                rule.service = " ".join(service_tokens) or "Any"

            rules.append(rule)

    return rules


def parse_manual_nat_rules(
    output: str,
    objects: Dict[str, NetworkObject],
) -> List[NatRule]:
    rules: List[NatRule] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.lower().startswith("nat ") or " source " not in f" {line.lower()} ":
            continue

        tokens = line.split()
        if len(tokens) < 6:
            continue

        interface_in, interface_out = parse_interface_pair(tokens[1])
        try:
            source_index = tokens.index("source")
        except ValueError:
            continue

        if source_index + 3 >= len(tokens):
            continue

        source_mode = tokens[source_index + 1].lower()
        source_original = tokens[source_index + 2]
        source_translated = tokens[source_index + 3]
        translated_destination = "Any"
        original_destination = "Any"
        destination_mode = ""
        service = "Any"

        cursor = source_index + 4
        if cursor < len(tokens) and tokens[cursor].lower() == "destination":
            if cursor + 4 >= len(tokens):
                continue
            destination_mode = tokens[cursor + 1].lower()
            original_destination = tokens[cursor + 2]
            translated_destination = tokens[cursor + 3]
            cursor += 4

        if cursor < len(tokens) and tokens[cursor].lower() == "service":
            service = " ".join(tokens[cursor + 1 :]) or "Any"

        has_service = service != "Any"
        translation_descriptor = f"{source_mode} {source_translated}"
        if destination_mode:
            translation_descriptor += f" {destination_mode} {translated_destination}"

        rules.append(
            NatRule(
                original_source=resolve_object(source_original, objects),
                original_destination=resolve_object(original_destination, objects),
                translated_source=resolve_object(source_translated, objects),
                translated_destination=resolve_object(translated_destination, objects),
                service=service,
                interface_in=interface_in,
                interface_out=interface_out,
                rule_name=f"manual-nat-{len(rules) + 1}",
                nat_type=nat_type_from_translation(translation_descriptor, has_service),
                comments="Manual NAT rule",
            )
        )

    return rules


def rule_to_row(
    host: str,
    model: str,
    rule: NatRule,
    rule_id: int,
) -> Dict[str, str]:
    return {
        "Device Name": host,
        "Management IP": host,
        "Vendor": "Cisco",
        "Model": model,
        "NAT Type": rule.nat_type,
        "Original Source Network": rule.original_source,
        "Original Destination Network": rule.original_destination,
        "Translated Source": rule.translated_source,
        "Translated Destination": rule.translated_destination,
        "Service/Port": rule.service,
        "Interface In": rule.interface_in,
        "Interface Out": rule.interface_out,
        "Rule Name": rule.rule_name,
        "Rule ID": str(rule_id),
        "Enabled/Disabled": "Enabled",
        "Comments": rule.comments,
    }


def collect_host(host: str, username: str, password: str, device_type: str) -> List[Dict[str, str]]:
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise RuntimeError(
            "Netmiko is not installed. Install it with: python -m pip install netmiko"
        ) from exc

    connection = None
    try:
        connection = ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            conn_timeout=30,
            auth_timeout=30,
            banner_timeout=30,
        )
        version_output = send_command(connection, "show version")
        object_output = send_command(connection, "show running-config object network")
        nat_output = send_command(connection, "show running-config nat")

        model = parse_model(version_output)
        objects = parse_network_objects(object_output)
        rules = parse_object_nat_rules(objects)
        rules.extend(parse_manual_nat_rules(nat_output, objects))

        return [rule_to_row(host, model, rule, index) for index, rule in enumerate(rules, start=1)]
    finally:
        if connection is not None:
            connection.disconnect()


def write_report(path: Path, rows: Iterable[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=REPORT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    try:
        hosts = prompt_hosts()
        username = input("SSH user ID: ").strip()
        if not username:
            raise ValueError("SSH user ID is required.")
        password = getpass.getpass("SSH password: ")
        if not password:
            raise ValueError("SSH password is required.")
        device_type = prompt_device_type()
        output_path = prompt_output_path()
    except (ValueError, EOFError, KeyboardInterrupt) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    all_rows: List[Dict[str, str]] = []
    worker_count = min(DEFAULT_WORKERS, len(hosts))
    print(f"Collecting from {len(hosts)} host(s) using {worker_count} worker(s)...", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_host = {
            executor.submit(collect_host, host, username, password, device_type): host
            for host in hosts
        }
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            print(f"Collecting NAT rules from {host}...", file=sys.stderr)
            try:
                rows = future.result()
                if rows:
                    all_rows.extend(rows)
                    print(f"  Collected {len(rows)} NAT rule(s).", file=sys.stderr)
                else:
                    print("  No supported NAT rules found.", file=sys.stderr)
            except Exception as exc:
                print(f"  FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)

    try:
        write_report(output_path, all_rows)
    except OSError as exc:
        print(f"Could not write report: {exc}", file=sys.stderr)
        return 1

    print(f"Report written to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
