#!/usr/bin/env python3

"""Display NetBrain R12 devices and interfaces for a requested site."""

import argparse
import csv
import getpass
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGIN_PATH = "/ServicesAPI/API/V1/Session"
DEVICES_PATH = "/ServicesAPI/API/V1/CMDB/Devices"
DEFAULT_INTERFACES_PATH = "/ServicesAPI/API/V1/CMDB/Devices/{device_id}/Interfaces"
DEFAULT_BASE_URL = "https://netbrain.mckesson.com"
DEFAULT_SITE_FILTER = "DDC1"
DEFAULT_PAGE_SIZE = 50
DEFAULT_MAX_PAGES = 100


class NetBrainClient:
    def __init__(self, base_url: str, insecure: bool = False, timeout: int = 60):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = not insecure
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = path if path.startswith(("http://", "https://")) else self.base_url + path
        response = self.session.request(
            method=method,
            url=url,
            timeout=self.timeout,
            **kwargs,
        )

        if not response.ok:
            body = response.text[:1500].replace("\n", " ")
            raise RuntimeError(f"HTTP {response.status_code} from {url}: {body}")

        if not response.text.strip():
            return {}

        try:
            return response.json()
        except ValueError as error:
            body = response.text[:1500].replace("\n", " ")
            raise RuntimeError(
                f"NetBrain returned a non-JSON response from {url}: {body}"
            ) from error

    def login(self, username: str, password: str, tenant_name: str = "", domain_name: str = "") -> None:
        payload = {"username": username, "password": password}
        if tenant_name:
            payload["tenantName"] = tenant_name
        if domain_name:
            payload["domainName"] = domain_name

        response = self.request("POST", LOGIN_PATH, json=payload)
        token = first_value(response, (
            "token", "Token", "accessToken", "access_token",
            "data.token", "data.accessToken", "result.token", "result.accessToken",
        ))
        if not token:
            raise RuntimeError(
                "Login returned no token:\n" + json.dumps(response, indent=2, default=str)[:5000]
            )

        self.session.headers.update({
            "Token": str(token),
            "Authorization": f"Bearer {token}",
        })
        print("Successfully authenticated")

    def get_devices(
        self,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages: int = DEFAULT_MAX_PAGES,
        page_param: str = "pageNo",
        page_size_param: str = "pageSize",
    ) -> Tuple[List[Dict[str, Any]], List[Any]]:
        """Return unique devices and every raw page response.

        NetBrain installations vary in pagination names and indexing. The
        first request is unmodified, then the script probes common patterns
        until one returns records not already seen. It continues only with a
        pattern that produces new unique records, preventing duplicate pages
        from being mistaken for a complete inventory.
        """
        all_devices: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str, str]] = set()
        raw_responses: List[Any] = []

        def absorb(response: Any, label: str) -> Tuple[int, int]:
            records = extract_records(response, (
                "devices", "deviceList", "records", "items", "results", "data",
            ))
            page_devices = [record for record in records if isinstance(record, dict)]
            new_count = 0
            for device in page_devices:
                key = device_key(device)
                if key not in seen:
                    seen.add(key)
                    all_devices.append(device)
                    new_count += 1
            print(
                f"Retrieved {label}: {len(page_devices)} records "
                f"({new_count} new; {len(all_devices)} total unique)"
            )
            return len(page_devices), new_count

        first_response = self.request("GET", DEVICES_PATH)
        raw_responses.append(first_response)
        first_count, _ = absorb(first_response, "initial device page")

        # Each tuple is (label, query-builder, first value representing the
        # second page). The initial unmodified response is treated as page 1.
        candidates = [
            (
                "configured pagination",
                lambda value: {page_param: value, page_size_param: page_size},
                2,
            ),
            (
                "pageNo/pageSize (zero-based probe)",
                lambda value: {"pageNo": value, "pageSize": page_size},
                1,
            ),
            (
                "pageIndex/pageSize",
                lambda value: {"pageIndex": value, "pageSize": page_size},
                1,
            ),
            (
                "page/pageSize",
                lambda value: {"page": value, "pageSize": page_size},
                2,
            ),
            (
                "offset/limit",
                lambda value: {"offset": value, "limit": page_size},
                page_size,
            ),
            (
                "start/limit",
                lambda value: {"start": value, "limit": page_size},
                page_size,
            ),
            (
                "skip/limit",
                lambda value: {"skip": value, "limit": page_size},
                page_size,
            ),
        ]

        tried: Set[Tuple[str, str]] = set()
        active = None
        probe_response: Any = None
        probe_value = None

        for label, query_builder, first_value in candidates:
            query = query_builder(first_value)
            signature = tuple(sorted((str(key), str(value)) for key, value in query.items()))
            if signature in tried:
                continue
            tried.add(signature)

            try:
                response = self.request("GET", DEVICES_PATH, params=query)
            except Exception as error:
                print(f"Pagination probe failed ({label}): {error}")
                continue

            raw_responses.append(response)
            page_count, new_count = absorb(response, f"{label} probe")
            if new_count > 0:
                active = (label, query_builder)
                probe_response = response
                probe_value = first_value
                print(f"Using pagination pattern: {label}")
                break
            if page_count == 0:
                continue

        if active is not None and probe_response is not None and probe_value is not None:
            label, query_builder = active
            for page_number in range(1, max_pages + 1):
                value = probe_value + page_number
                try:
                    response = self.request(
                        "GET",
                        DEVICES_PATH,
                        params=query_builder(value),
                    )
                except Exception as error:
                    print(f"Pagination stopped at {label} value {value}: {error}")
                    break

                raw_responses.append(response)
                page_count, new_count = absorb(response, f"{label} value {value}")
                if page_count == 0 or new_count == 0 or page_count < page_size:
                    break

        if first_count == page_size and active is None:
            print(
                "WARNING: The API returned exactly one full page but none of the "
                "pagination patterns produced new records. The endpoint may require "
                "a NetBrain-specific filter or a different request method."
            )

        return all_devices, raw_responses

    def get_interfaces(
        self,
        device: Dict[str, Any],
        path_template: str,
        method: str = "GET",
    ) -> List[Dict[str, Any]]:
        device_id = first_value(device, (
            "id", "deviceId", "deviceID", "device_id", "uuid",
        ))
        if device_id in (None, ""):
            raise RuntimeError("Device has no ID")

        path = path_template.format(
            device_id=str(device_id),
            id=str(device_id),
            name=str(first_value(device, ("name", "deviceName", "hostName", "hostname"), "")),
        )
        response = self.request(method.upper(), path)
        records = extract_records(response, (
            "interfaces", "ports", "interfaceList", "records", "items", "results", "data",
        ))
        return [record for record in records if isinstance(record, dict)]


def first_value(obj: Any, paths: Iterable[str], default: Any = None) -> Any:
    """Read a value using case-insensitive key matching."""
    for path in paths:
        value = obj
        found = True
        for part in path.split("."):
            if not isinstance(value, dict):
                found = False
                break

            if part in value:
                value = value[part]
                continue

            normalized_part = re_key(part)
            matching_key = next(
                (key for key in value if re_key(key) == normalized_part),
                None,
            )
            if matching_key is None:
                found = False
                break
            value = value[matching_key]

        if found and value not in (None, ""):
            return value
    return default


def extract_records(response: Any, preferred_keys: Iterable[str]) -> List[Any]:
    if isinstance(response, list):
        return response
    if not isinstance(response, dict):
        return []

    preferred = {str(key).lower() for key in preferred_keys}
    for key, value in response.items():
        if str(key).lower() in preferred:
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = extract_records(value, preferred_keys)
                if nested:
                    return nested

    for key in ("result", "response", "payload", "data"):
        value = response.get(key)
        if isinstance(value, (dict, list)):
            nested = extract_records(value, preferred_keys)
            if nested:
                return nested

    if response and all(isinstance(value, dict) for value in response.values()):
        return list(response.values())
    return []


def find_first_key(obj: Any, wanted_keys: Set[str]) -> Optional[Any]:
    wanted = {re_key(key) for key in wanted_keys}
    if isinstance(obj, dict):
        for key, value in obj.items():
            if re_key(key) in wanted and value not in (None, "", False):
                if isinstance(value, (str, int, float)):
                    return value
            found = find_first_key(value, wanted_keys)
            if found not in (None, ""):
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = find_first_key(value, wanted_keys)
            if found not in (None, ""):
                return found
    return None


def find_boolean_key(obj: Any, wanted_keys: Set[str]) -> Optional[bool]:
    wanted = {re_key(key) for key in wanted_keys}
    if isinstance(obj, dict):
        for key, value in obj.items():
            if re_key(key) in wanted and isinstance(value, bool):
                return value
            found = find_boolean_key(value, wanted_keys)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for value in obj:
            found = find_boolean_key(value, wanted_keys)
            if found is not None:
                return found
    return None


def find_number_key(obj: Any, wanted_keys: Set[str]) -> Optional[int]:
    value = find_first_key(obj, wanted_keys)
    if isinstance(value, bool):
        return None
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def re_key(value: Any) -> str:
    return "".join(character.lower() for character in str(value) if character.isalnum())


def flatten_strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for nested in value.values():
            yield from flatten_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from flatten_strings(nested)
    elif value not in (None, ""):
        yield str(value)


def values_for_keys(obj: Any, names: Iterable[str]) -> List[str]:
    wanted = {re_key(name) for name in names}
    values: List[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if re_key(key) in wanted:
                    values.extend(flatten_strings(nested))
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(obj)
    return values


def device_name(device: Dict[str, Any]) -> str:
    return str(first_value(device, (
        "name", "deviceName", "hostName", "hostname", "displayName",
    ), ""))


def management_ip(device: Dict[str, Any]) -> str:
    return str(first_value(device, (
        "mgmtIP", "managementIP", "managementIp", "management_ip",
        "ip", "ipAddress", "managementAddress",
    ), ""))


def device_id(device: Dict[str, Any]) -> str:
    return str(first_value(device, (
        "id", "deviceId", "deviceID", "device_id", "uuid",
    ), ""))


def site_text(device: Dict[str, Any]) -> str:
    values = values_for_keys(device, (
        "site", "siteName", "sitePath", "location", "locationName",
        "group", "groupName", "container", "containerName", "domain",
        "domainName", "path", "tags", "labels",
    ))
    return "; ".join(dict.fromkeys(values))


def device_type(device: Dict[str, Any]) -> str:
    values = values_for_keys(device, (
        "subTypeName", "deviceType", "deviceClass", "category", "platform",
        "vendor", "model", "type",
    ))
    return "; ".join(dict.fromkeys(values))


def matches_site(device: Dict[str, Any], site_filter: str) -> bool:
    if not site_filter:
        return True
    needle = site_filter.casefold()
    searchable = " ".join(flatten_strings(device)).casefold()
    return needle in searchable


def is_switch(device: Dict[str, Any]) -> bool:
    searchable = " ".join(flatten_strings(device)).casefold()
    switch_terms = (
        "switch", "catalyst", "nexus", "n9k", "n3k", "n5k", "n7k",
        "arista", "eos", "nx-os", "nxos", "ios-xe", "leaf", "spine",
    )
    router_terms = ("router", "firewall", "load balancer", "wireless controller")
    if any(term in searchable for term in router_terms) and "switch" not in searchable:
        return False
    return any(term in searchable for term in switch_terms)


def device_key(device: Dict[str, Any]) -> Tuple[str, str, str]:
    identity = (
        device_id(device).casefold(),
        device_name(device).casefold(),
        management_ip(device).casefold(),
    )
    if any(identity):
        return identity

    # Preserve records even when an API response uses unfamiliar identity
    # field names. Without this fallback, every such record becomes ("", "", "")
    # and deduplication incorrectly keeps only one device.
    canonical = json.dumps(device, sort_keys=True, default=str, separators=(",", ":"))
    return ("raw:" + canonical, "", "")


def interface_value(interface: Dict[str, Any], names: Iterable[str]) -> str:
    value = first_value(interface, names, "")
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), default=str)
    return str(value)


def normalize_interface(device: Dict[str, Any], interface: Dict[str, Any], match_status: str) -> Dict[str, str]:
    return {
        "Device": device_name(device),
        "ManagementIP": management_ip(device),
        "DeviceType": device_type(device),
        "DeviceID": device_id(device),
        "SiteFilter": DEFAULT_SITE_FILTER,
        "MatchStatus": match_status,
        "Interface": interface_value(interface, ("name", "interfaceName", "ifName", "portName", "port", "displayName")),
        "Description": interface_value(interface, ("description", "desc", "interfaceDescription")),
        "AdminStatus": interface_value(interface, ("adminStatus", "administrativeStatus", "admin_state")),
        "OperStatus": interface_value(interface, ("operStatus", "operationalStatus", "status", "linkStatus")),
        "Speed": interface_value(interface, ("speed", "bandwidth", "interfaceSpeed", "speedMbps")),
        "VLAN": interface_value(interface, ("vlan", "vlanId", "vlanID", "accessVlan", "nativeVlan")),
        "IPAddress": interface_value(interface, ("ipAddress", "ip", "ipv4Address", "ipv6Address")),
    }


def write_json(value: Any, filename: str) -> None:
    Path(filename).write_text(json.dumps(value, indent=2, default=str), encoding="utf-8")


def flatten_json(value: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten nested JSON objects into CSV columns; preserve arrays as JSON text."""
    flattened: Dict[str, Any] = {}
    if isinstance(value, dict):
        for key, nested in value.items():
            column = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(flatten_json(nested, column))
    elif isinstance(value, list):
        flattened[prefix] = json.dumps(value, ensure_ascii=False, default=str)
    else:
        flattened[prefix] = "" if value is None else value
    return flattened


def write_all_json_columns_csv(raw_responses: Any, filename: str) -> int:
    """Write every device JSON field to a flattened CSV column."""
    pages = raw_responses if isinstance(raw_responses, list) else [raw_responses]
    rows: List[Dict[str, Any]] = []

    for page_number, response in enumerate(pages, start=1):
        records = extract_records(response, (
            "devices", "deviceList", "records", "items", "results", "data",
        ))
        for record_number, record in enumerate(records, start=1):
            if isinstance(record, dict):
                row: Dict[str, Any] = {
                    "_source_page": page_number,
                    "_source_record": record_number,
                }
                row.update(flatten_json(record))
                rows.append(row)

    if not rows:
        return 0

    columns = ["_source_page", "_source_record"]
    for row in rows:
        for column in row:
            if column not in columns:
                columns.append(column)

    with open(filename, "w", newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def write_devices_csv(devices: List[Dict[str, Any]], site_filter: str, filename: str) -> None:
    fields = [
        "Name", "ManagementIP", "DeviceType", "DeviceID", "Site",
        "SiteFilter", "MatchStatus", "IsSwitch",
    ]
    with open(filename, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        for device in devices:
            writer.writerow({
                "Name": device_name(device),
                "ManagementIP": management_ip(device),
                "DeviceType": device_type(device),
                "DeviceID": device_id(device),
                "Site": site_text(device),
                "SiteFilter": site_filter,
                "MatchStatus": "MATCHED" if matches_site(device, site_filter) else "NOT_MATCHED",
                "IsSwitch": "YES" if is_switch(device) else "NO",
            })


def write_interfaces_csv(rows: List[Dict[str, str]], filename: str) -> None:
    fields = [
        "Device", "ManagementIP", "DeviceType", "DeviceID", "SiteFilter",
        "MatchStatus", "Interface", "Description", "AdminStatus",
        "OperStatus", "Speed", "VLAN", "IPAddress",
    ]
    with open(filename, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def display_devices(devices: List[Dict[str, Any]], site_filter: str, title: str) -> None:
    print("\n" + "=" * 150)
    print(title)
    print("=" * 150)
    print(f"{'Device':<42}{'ManagementIP':<18}{'DeviceType':<32}{'Site/Location':<38}{'Match':<12}")
    print("-" * 150)
    for device in devices:
        status = "MATCHED" if matches_site(device, site_filter) else "NOT_MATCHED"
        print(
            f"{device_name(device)[:41]:<42}"
            f"{management_ip(device)[:17]:<18}"
            f"{device_type(device)[:31]:<32}"
            f"{site_text(device)[:37]:<38}"
            f"{status:<12}"
        )


def display_interfaces(rows: List[Dict[str, str]]) -> None:
    print("\n" + "=" * 170)
    print(f"{DEFAULT_SITE_FILTER} DEVICE INTERFACES")
    print("=" * 170)
    print(
        f"{'Device':<35}{'IP':<16}{'Interface':<24}{'Admin':<14}"
        f"{'Oper':<14}{'Speed':<14}{'VLAN':<10}{'Description':<42}"
    )
    print("-" * 170)
    for row in rows:
        print(
            f"{row['Device'][:34]:<35}"
            f"{row['ManagementIP'][:15]:<16}"
            f"{row['Interface'][:23]:<24}"
            f"{row['AdminStatus'][:13]:<14}"
            f"{row['OperStatus'][:13]:<14}"
            f"{row['Speed'][:13]:<14}"
            f"{row['VLAN'][:9]:<10}"
            f"{row['Description'][:41]:<42}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Display NetBrain R12 devices and interfaces for site DDC1."
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    security_group = parser.add_mutually_exclusive_group()
    security_group.add_argument(
        "--secure",
        dest="insecure",
        action="store_false",
        help="Enable TLS certificate verification (default).",
    )
    security_group.add_argument(
        "--insecure",
        dest="insecure",
        action="store_true",
        help="Disable TLS certificate verification only when required.",
    )
    parser.set_defaults(insecure=True)
    parser.add_argument("--tenant-name", default="", help="Optional tenant sent during login.")
    parser.add_argument(
        "--domain-name",
        default="",
        help="Optional NetBrain domain sent during login. Leave blank unless DDC1 is the actual domain.",
    )
    parser.add_argument("--site-filter", default=DEFAULT_SITE_FILTER, help="Text used to identify the site. Default: DDC1")
    parser.add_argument(
        "--strict-filter",
        action="store_true",
        help="Do not fall back to displaying all API records when no site match is found.",
    )
    parser.add_argument(
        "--interfaces-path-template",
        default=DEFAULT_INTERFACES_PATH,
        help="Interface endpoint path template with {device_id}, {id}, or {name}.",
    )
    parser.add_argument("--interfaces-method", choices=("GET", "POST"), default="GET")
    parser.add_argument("--devices-page-param", default="pageNo")
    parser.add_argument("--devices-page-size-param", default="pageSize")
    parser.add_argument("--devices-page-size", type=int, default=DEFAULT_PAGE_SIZE)
    parser.add_argument("--devices-max-pages", type=int, default=DEFAULT_MAX_PAGES)
    parser.add_argument("--csv-file", default="ddc1_switch_interfaces.csv")
    parser.add_argument("--raw-json-file", default="netbrain_devices_raw.json")
    parser.add_argument("--all-columns-csv-file", default="netbrain_devices_all_columns.csv")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.devices_page_size <= 0 or args.devices_max_pages <= 0:
        print("Error: pagination values must be positive.", file=sys.stderr)
        return 2

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    client = NetBrainClient(args.base_url, insecure=args.insecure)

    print(f"NetBrain URL: {args.base_url}")
    print(f"TLS certificate verification: {'disabled' if args.insecure else 'enabled'}")

    try:
        print("\nLogging into NetBrain...")
        client.login(username, password, args.tenant_name, args.domain_name)

        print("\nRetrieving devices...")
        all_devices, raw_responses = client.get_devices(
            page_size=args.devices_page_size,
            max_pages=args.devices_max_pages,
            page_param=args.devices_page_param,
            page_size_param=args.devices_page_size_param,
        )
        write_json(raw_responses, args.raw_json_file)
        all_columns_count = write_all_json_columns_csv(
            raw_responses,
            args.all_columns_csv_file,
        )
        print(
            f"All-column CSV saved to: {args.all_columns_csv_file} "
            f"({all_columns_count} records)"
        )

        matched_devices = [
            device for device in all_devices
            if matches_site(device, args.site_filter)
        ]
        matched_switches = [device for device in matched_devices if is_switch(device)]

        print(f"\nTotal unique devices returned: {len(all_devices)}")
        print(f"Devices matching {args.site_filter!r}: {len(matched_devices)}")
        print(f"Switches matching {args.site_filter!r}: {len(matched_switches)}")
        print(f"Raw API response saved to: {args.raw_json_file}")

        if matched_devices:
            report_devices = matched_devices
            report_title = f"{args.site_filter} DEVICES"
        elif args.strict_filter:
            report_devices = []
            report_title = f"{args.site_filter} DEVICES - NO MATCHES"
            print("No matching records; --strict-filter prevented fallback output.")
        else:
            # Never silently create a blank report. These records are not
            # asserted to be DDC1; the Match column makes that distinction clear.
            report_devices = all_devices
            report_title = (
                f"API DEVICES RETURNED - NO {args.site_filter} MATCHES "
                "(FALLBACK INVENTORY)"
            )
            print(
                f"Warning: NetBrain returned no record containing {args.site_filter!r}. "
                "Displaying all returned records with Match=NOT_MATCHED."
            )

        display_devices(report_devices, args.site_filter, report_title)
        device_csv = args.csv_file.rsplit(".", 1)[0] + "_devices.csv"
        write_devices_csv(report_devices, args.site_filter, device_csv)
        print(f"Device CSV saved to: {device_csv}")

        rows: List[Dict[str, str]] = []
        for device in report_devices:
            if matched_devices and not matches_site(device, args.site_filter):
                continue
            match_status = "MATCHED" if matches_site(device, args.site_filter) else "NOT_MATCHED"
            name = device_name(device) or device_id(device) or management_ip(device) or "<unnamed>"
            try:
                interfaces = client.get_interfaces(
                    device,
                    args.interfaces_path_template,
                    args.interfaces_method,
                )
                for interface in interfaces:
                    rows.append(normalize_interface(device, interface, match_status))
                print(f"{name}: {len(interfaces)} interfaces")
            except Exception as error:
                print(f"{name}: interface lookup failed: {error}")

        rows.sort(key=lambda row: (row["Device"].casefold(), row["Interface"].casefold()))
        display_interfaces(rows)
        write_interfaces_csv(rows, args.csv_file)
        print(f"\nInterface CSV saved to: {args.csv_file}")
        return 0

    except Exception as error:
        print(f"NetBrain query failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
