#!/usr/bin/env python3
"""Collect Cisco NAT/PAT data and write the switch_nat_report CSV format.

Live collection with prompts:
    python generate_switch_nat_report.py --output switch_nat_report.csv
    # Prompts for User ID, Password, and comma-delimited devices.

Live collection from an inventory file:
    python generate_switch_nat_report.py --inventory inventory.csv \
        --output switch_nat_report.csv

Offline parsing of saved command output:
    python generate_switch_nat_report.py --raw-dir command_outputs \
        --output switch_nat_report.csv

Inventory CSV columns:
    Device,Host,Username,Password,Port,Device_Type

Password may be omitted from the inventory and supplied with --password-env
or interactively. Keep credentials out of source control.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from typing import TypedDict
except ImportError:  # pragma: no cover - Python 3.7 compatibility
    from typing_extensions import TypedDict

LOG = logging.getLogger("switch_nat_report")

OUTPUT_FIELDS = [
    "Device",
    "Platform",
    "Record_Type",
    "Command",
    "Inside_Local",
    "Inside_Global",
    "Outside_Local",
    "Outside_Global",
    "Details",
]

TRANSLATIONS_COMMAND = "show ip nat translations"
STATISTICS_COMMAND = "show ip nat statistics"
COMMANDS = (TRANSLATIONS_COMMAND, STATISTICS_COMMAND)

# Cisco output can contain IPv4 addresses with or without port numbers.
ENDPOINT_RE = re.compile(
    r"(?<![\w.])"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"(?::(?P<port>\d+))?"
    r"(?![\w.])"
)
TRANSLATION_HEADER_RE = re.compile(
    r"(?:pro|protocol).*inside\s+global.*inside\s+local",
    re.IGNORECASE,
)
PROMPT_RE = re.compile(r"^[\w.@:/-]+(?:#|>)$")


class InventoryRow(TypedDict, total=False):
    Device: str
    Host: str
    Username: str
    Password: str
    Port: str
    Device_Type: str


def make_row(
    device: str,
    record_type: str,
    command: str,
    details: str,
    inside_local: str = "",
    inside_global: str = "",
    outside_local: str = "",
    outside_global: str = "",
) -> Dict[str, str]:
    return {
        "Device": device,
        "Platform": "cisco_nxos",
        "Record_Type": record_type,
        "Command": command,
        "Inside_Local": inside_local,
        "Inside_Global": inside_global,
        "Outside_Local": outside_local,
        "Outside_Global": outside_global,
        "Details": details,
    }


def is_noise(line: str, command: str) -> bool:
    """Return True for blank lines, command echoes, prompts, and pager text."""
    stripped = line.strip()
    if not stripped:
        return True
    if stripped == command:
        return True
    if PROMPT_RE.fullmatch(stripped):
        return True
    if stripped in {"--More--", "--More-- ", "terminal length 0"}:
        return True
    return False


def parse_translations(device: str, output: str) -> List[Dict[str, str]]:
    """Parse show ip nat translations into the attached report schema.

    The attached report places the first three endpoint values in
    Inside_Local, Inside_Global, and Outside_Local, respectively, and leaves
    Outside_Global blank. This preserves that report's established layout;
    the complete original line remains in Details.
    """
    rows: List[Dict[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if is_noise(line, TRANSLATIONS_COMMAND):
            continue

        if TRANSLATION_HEADER_RE.search(line):
            rows.append(make_row(device, "NAT", TRANSLATIONS_COMMAND, line))
            continue

        endpoints = [m.group("ip") for m in ENDPOINT_RE.finditer(line)]
        if len(endpoints) >= 3:
            rows.append(
                make_row(
                    device,
                    "NAT",
                    TRANSLATIONS_COMMAND,
                    line,
                    inside_local=endpoints[0],
                    inside_global=endpoints[1],
                    outside_local=endpoints[2],
                    # Deliberately blank for compatibility with the attached report.
                    outside_global="",
                )
            )
        else:
            # Preserve unexpected/non-tabular lines for troubleshooting rather
            # than silently dropping evidence from the device.
            rows.append(make_row(device, "NAT", TRANSLATIONS_COMMAND, line))
    return rows


def classify_statistics_line(line: str) -> Tuple[str, str]:
    """Return (record type, cleaned details) for one statistics line."""
    explicit = re.match(r"^(NAT|PAT)\s{2,}(.*)$", line, re.IGNORECASE)
    if explicit:
        return explicit.group(1).upper(), explicit.group(2).strip()

    lower = line.lower()
    if "port block alloc fail" in lower:
        return "PAT", line

    # The sample report identifies PAT interface groups by PAT subinterfaces
    # and Port-channel NAT/PAT interfaces. This heuristic covers that format
    # when the switch output does not label the rows explicitly.
    if ("port-channel" in lower or "portchannel" in lower) and "." in line:
        return "PAT", line
    if re.search(r"\.30[0-3]\b|\.31[0-3]\b|\.502\b", line):
        return "PAT", line

    return "NAT", line


def parse_statistics(device: str, output: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if is_noise(line, STATISTICS_COMMAND):
            continue
        record_type, details = classify_statistics_line(line)
        rows.append(make_row(device, record_type, STATISTICS_COMMAND, details))
    return rows


def parse_device_outputs(
    device: str, translations_output: str, statistics_output: str
) -> List[Dict[str, str]]:
    return parse_translations(device, translations_output) + parse_statistics(
        device, statistics_output
    )


def prompt_live_inventory() -> List[InventoryRow]:
    """Prompt for credentials and comma-delimited device hostnames."""
    devices_text = input("Devices/IPs (comma-delimited): ").strip()
    devices = [device.strip() for device in devices_text.split(",") if device.strip()]
    if not devices:
        raise ValueError("At least one device hostname or IP address is required.")

    username = input("User ID: ").strip()
    if not username:
        raise ValueError("A user ID is required.")
    password = getpass.getpass("Password: ")
    if not password:
        raise ValueError("A password is required.")

    # Store credentials in memory only; they are not written to the report.
    return [
        {
            "Device": device,
            "Host": device,
            "Username": username,
            "Password": password,
            "Port": "22",
            "Device_Type": "cisco_nxos",
        }
        for device in devices
    ]


def read_inventory(path: Path) -> List[InventoryRow]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"Inventory is empty: {path}")

    required = {"Device", "Host"}
    missing = required - set(rows[0])
    if missing:
        raise ValueError(
            f"Inventory must contain columns {sorted(required)}; missing {sorted(missing)}"
        )

    result: List[InventoryRow] = []
    for index, row in enumerate(rows, start=2):
        device = (row.get("Device") or "").strip()
        host = (row.get("Host") or "").strip()
        if not device or not host:
            raise ValueError(f"Inventory row {index} must have Device and Host")
        result.append({key: (value or "").strip() for key, value in row.items()})
    return result


def load_credentials(
    inventory: Sequence[InventoryRow], password_env: str, prompt_password: bool
) -> Tuple[str, str]:
    username = next((r.get("Username", "") for r in inventory if r.get("Username")), "")
    password = next((r.get("Password", "") for r in inventory if r.get("Password")), "")
    username = username or os.getenv("NETMIKO_USERNAME", "")
    password = password or os.getenv(password_env, "")

    if not username:
        username = input("Username: ").strip()
    if not password and prompt_password:
        password = getpass.getpass("Password: ")
    if not username or not password:
        raise ValueError(
            "Credentials are missing. Set NETMIKO_USERNAME and "
            f"{password_env}, add them to inventory, or use interactive prompts."
        )
    return username, password


def collect_one(
    inventory_row: InventoryRow,
    username: str,
    password: str,
    timeout: int,
) -> Tuple[str, List[Dict[str, str]]]:
    # Lazy import keeps offline parsing usable without Netmiko installed.
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise RuntimeError(
            "Live collection requires Netmiko. Install it with: pip install netmiko"
        ) from exc

    device = inventory_row["Device"]
    params = {
        "device_type": inventory_row.get("Device_Type") or "cisco_nxos",
        "host": inventory_row["Host"],
        "username": inventory_row.get("Username") or username,
        "password": inventory_row.get("Password") or password,
        "port": int(inventory_row.get("Port") or 22),
        "conn_timeout": timeout,
        "auth_timeout": timeout,
        "banner_timeout": timeout,
        "fast_cli": False,
    }

    connection = None
    try:
        connection = ConnectHandler(**params)
        translations = connection.send_command(
            TRANSLATIONS_COMMAND,
            read_timeout=timeout,
            strip_prompt=False,
            strip_command=False,
        )
        statistics = connection.send_command(
            STATISTICS_COMMAND,
            read_timeout=timeout,
            strip_prompt=False,
            strip_command=False,
        )
        return device, parse_device_outputs(device, translations, statistics)
    finally:
        if connection:
            connection.disconnect()


def collect_live(
    inventory: Sequence[InventoryRow],
    username: str,
    password: str,
    timeout: int,
    workers: int,
) -> List[Dict[str, str]]:
    collected: Dict[str, List[Dict[str, str]]] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {
            executor.submit(collect_one, row, username, password, timeout): row
            for row in inventory
        }
        for future in as_completed(futures):
            row = futures[future]
            device = row["Device"]
            try:
                name, records = future.result()
                collected[name] = records
                LOG.info("Collected %d records from %s", len(records), name)
            except Exception as exc:
                LOG.error("%s failed: %s", device, exc)

    # Keep output deterministic and match the inventory order.
    output: List[Dict[str, str]] = []
    for row in inventory:
        output.extend(collected.get(row["Device"], []))
    return output


def raw_file_candidates(raw_dir: Path, device: str, command: str) -> Iterable[Path]:
    safe_device = re.sub(r"[^A-Za-z0-9_.-]+", "_", device)
    safe_command = command.replace(" ", "_")
    yield raw_dir / f"{safe_device}__{safe_command}.txt"
    yield raw_dir / f"{device}__{safe_command}.txt"


def read_raw_output(raw_dir: Path, device: str, command: str) -> str:
    for candidate in raw_file_candidates(raw_dir, device, command):
        if candidate.exists():
            return candidate.read_text(encoding="utf-8", errors="replace")
    expected = next(raw_file_candidates(raw_dir, device, command))
    raise FileNotFoundError(f"Missing raw command output: {expected}")


def parse_raw_directory(inventory: Sequence[InventoryRow], raw_dir: Path) -> List[Dict[str, str]]:
    output: List[Dict[str, str]] = []
    for row in inventory:
        device = row["Device"]
        translations = read_raw_output(raw_dir, device, TRANSLATIONS_COMMAND)
        statistics = read_raw_output(raw_dir, device, STATISTICS_COMMAND)
        output.extend(parse_device_outputs(device, translations, statistics))
    return output


def write_report(rows: Sequence[Dict[str, str]], output: Path, encoding: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding=encoding, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect Cisco NX-OS NAT/PAT translations and statistics into CSV."
    )
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument(
        "--inventory",
        type=Path,
        help="CSV with Device and Host columns for live Netmiko collection. If omitted, prompts for devices.",
    )
    source.add_argument(
        "--raw-dir",
        type=Path,
        help="Directory containing saved command output files for offline parsing.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("switch_nat_report.csv"),
        help="Output CSV path (default: switch_nat_report.csv).",
    )
    parser.add_argument(
        "--encoding",
        default="utf-8-sig",
        help="Output encoding (default: utf-8-sig; cp1252 matches the attached file).",
    )
    parser.add_argument("--timeout", type=int, default=30, help="Device timeout in seconds.")
    parser.add_argument("--workers", type=int, default=15, help="Parallel device sessions.")
    parser.add_argument(
        "--password-env",
        default="NETMIKO_PASSWORD",
        help="Environment variable containing the shared password.",
    )
    parser.add_argument(
        "--no-password-prompt",
        action="store_true",
        help="Do not prompt if the password is missing; fail instead.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    try:
        if args.raw_dir:
            inventory_path = args.raw_dir / "inventory.csv"
            if not inventory_path.exists():
                raise ValueError(
                    f"Offline mode expects {inventory_path} so device names can be mapped."
                )
            inventory = read_inventory(inventory_path)
            rows = parse_raw_directory(inventory, args.raw_dir)
        else:
            if args.inventory:
                inventory = read_inventory(args.inventory)
                username, password = load_credentials(
                    inventory, args.password_env, not args.no_password_prompt
                )
            else:
                inventory = prompt_live_inventory()
                username = inventory[0]["Username"]
                password = inventory[0]["Password"]
            rows = collect_live(
                inventory, username, password, args.timeout, args.workers
            )

        write_report(rows, args.output, args.encoding)
        LOG.info("Wrote %d records to %s", len(rows), args.output)
        return 0 if rows else 2
    except (OSError, ValueError, FileNotFoundError, RuntimeError) as exc:
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
