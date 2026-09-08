#!/usr/bin/env python3
"""List STP VLANs and SVIs with a MODERATE shutdown recommendation.

This is a report-only script. It reads a CSV file, makes no network
connections, and does not change device configuration.
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


ALIASES = {
    "device": ("device", "hostname", "switch"),
    "vlan": ("vlan", "vlan id", "vlan_id", "vlan number"),
    "vlan_name": ("vlan_name", "vlan name", "name"),
    "svi_ip": ("svi_ip", "svi ip", "svi", "svi address"),
    "svi_mac": ("svi_mac", "svi mac"),
    "svi_description": ("svi_description", "svi description"),
    "recommendation": (
        "shutdown_recommendation",
        "shutdown recommendation",
        "recommendation",
    ),
    "reason": (
        "shutdown_recommendation_reason",
        "shutdown recommendation reason",
        "reason",
    ),
}


class ReportError(Exception):
    """Raised for invalid input or missing CSV fields."""


def normalize(value: object) -> str:
    return " ".join(str(value or "").strip().lower().replace("_", " ").split())


def find_column(fieldnames: Sequence[str], aliases: Iterable[str]) -> Optional[str]:
    normalized = {normalize(name): name for name in fieldnames if name}
    for alias in aliases:
        if normalize(alias) in normalized:
            return normalized[normalize(alias)]
    return None


def prompt_for_csv() -> Path:
    while True:
        raw = input("Enter the path to the STP VLAN CSV file: ").strip().strip('"')
        if not raw:
            print("A CSV path is required.")
            continue

        path = Path(raw).expanduser()
        if not path.is_file():
            print(f"File not found: {path}")
            continue
        if path.suffix.lower() != ".csv":
            print("The input file must have a .csv extension.")
            continue
        return path


def read_csv(path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    """Read Windows-1252 CSV exports, with UTF-8 fallback."""
    last_error: Optional[Exception] = None
    for encoding in ("cp1252", "utf-8-sig"):
        try:
            with path.open("r", encoding=encoding, newline="") as handle:
                sample = handle.read(8192)
                handle.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
                except csv.Error:
                    dialect = csv.excel

                reader = csv.DictReader(handle, dialect=dialect)
                if not reader.fieldnames:
                    raise ReportError("The CSV does not contain a header row.")
                rows = [row for row in reader if any(str(v or "").strip() for v in row.values())]
                return list(reader.fieldnames), rows
        except UnicodeDecodeError as exc:
            last_error = exc

    raise ReportError(f"Unable to decode the CSV file: {last_error}")


def resolve_columns(fieldnames: Sequence[str]) -> Dict[str, Optional[str]]:
    columns = {key: find_column(fieldnames, aliases) for key, aliases in ALIASES.items()}
    missing = [key for key in ("vlan", "recommendation") if not columns[key]]
    if missing:
        raise ReportError(
            "Missing required column(s): "
            + ", ".join(missing)
            + ". Required fields include VLAN and Shutdown_Recommendation."
        )
    return columns


def value(row: Dict[str, str], column: Optional[str]) -> str:
    return str(row.get(column, "") if column else "").strip()


def deduplicate(rows: Iterable[Dict[str, str]], key_fields: Sequence[str]) -> List[Dict[str, str]]:
    seen = set()
    result = []
    for row in rows:
        key = tuple(row[field] for field in key_fields)
        if key not in seen:
            seen.add(key)
            result.append(row)
    return result


def build_records(rows: Sequence[Dict[str, str]], columns: Dict[str, Optional[str]]) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    records = []
    for row in rows:
        if value(row, columns["recommendation"]).upper() != "MODERATE":
            continue

        record = {
            "device": value(row, columns["device"]),
            "vlan": value(row, columns["vlan"]),
            "vlan_name": value(row, columns["vlan_name"]),
            "svi_ip": value(row, columns["svi_ip"]),
            "svi_mac": value(row, columns["svi_mac"]),
            "svi_description": value(row, columns["svi_description"]),
            "reason": value(row, columns["reason"]),
        }
        records.append(record)

    vlan_records = deduplicate(records, ("device", "vlan", "vlan_name"))
    svi_records = [
        record
        for record in records
        if any(record[field] for field in ("svi_ip", "svi_mac", "svi_description"))
    ]
    svi_records = deduplicate(
        svi_records,
        ("device", "vlan", "svi_ip", "svi_mac", "svi_description"),
    )
    return vlan_records, svi_records


def write_report(source: Path, vlan_records: Sequence[Dict[str, str]], svi_records: Sequence[Dict[str, str]]) -> Path:
    output = source.with_name(f"{source.stem}_moderate_vlans_svis.csv")
    fields = [
        "type",
        "device",
        "vlan",
        "vlan_name",
        "svi_ip",
        "svi_mac",
        "svi_description",
        "reason",
    ]

    with output.open("w", encoding="cp1252", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in vlan_records:
            writer.writerow({"type": "VLAN", **record})
        for record in svi_records:
            writer.writerow({"type": "SVI", **record})
    return output


def print_records(title: str, records: Sequence[Dict[str, str]], include_svi: bool = False) -> None:
    print(f"\n{title}")
    if not records:
        print("  None found.")
        return

    for record in records:
        vlan_label = f"VLAN {record['vlan']}"
        if record["vlan_name"]:
            vlan_label += f" ({record['vlan_name']})"
        prefix = f"  {record['device']}: " if record["device"] else "  "
        line = prefix + vlan_label
        if include_svi:
            svi_parts = [record[field] for field in ("svi_ip", "svi_mac", "svi_description") if record[field]]
            line += " | SVI: " + ("; ".join(svi_parts) if svi_parts else "No SVI details")
        print(line)
        if record["reason"]:
            print(f"    Reason: {record['reason']}")


def main() -> int:
    print("STP moderate VLAN/SVI report (report-only)\n")
    source = prompt_for_csv()

    try:
        fieldnames, rows = read_csv(source)
        columns = resolve_columns(fieldnames)
        vlan_records, svi_records = build_records(rows, columns)
        output = write_report(source, vlan_records, svi_records)
    except (OSError, ReportError) as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1

    print_records("Moderate VLANs", vlan_records)
    print_records("Moderate SVIs", svi_records, include_svi=True)
    print(f"\nModerate VLAN count: {len(vlan_records)}")
    print(f"Moderate SVI count:  {len(svi_records)}")
    print(f"Report written to: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
