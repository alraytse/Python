#!/usr/bin/env python3

import argparse
import csv
import getpass
import json
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGIN_PATH = "/ServicesAPI/API/V1/Session"
DEVICES_PATH = "/ServicesAPI/API/V1/CMDB/Devices"
DEFAULT_INTERFACES_PATH = (
    "/ServicesAPI/API/V1/CMDB/Devices/{device_id}/Interfaces"
)
DEFAULT_PAGE_SIZE = 50
DEFAULT_MAX_PAGES = 100
DEFAULT_DOMAIN_NAME = "DDC1"


class NetBrainClient:
    def __init__(self, base_url: str, insecure: bool = False, timeout: int = 60):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = not insecure
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = path if path.startswith(("http://", "https://")) else self.base_url + path
        response = self.session.request(
            method=method,
            url=url,
            timeout=self.timeout,
            **kwargs,
        )

        if not response.ok:
            body = response.text[:1000].replace("\n", " ")
            raise RuntimeError(
                f"HTTP {response.status_code} from {url}: {body}"
            )

        if not response.text.strip():
            return {}

        content_type = response.headers.get("Content-Type", "")
        try:
            return response.json()
        except ValueError as error:
            body = response.text[:1000].replace("\n", " ")
            if "html" in content_type.lower() or body.lstrip().startswith("<"):
                raise RuntimeError(
                    f"NetBrain returned HTML instead of JSON from {url}. "
                    "Verify the R12 Web API hostname, protocol, and path."
                ) from error
            raise RuntimeError(
                f"Non-JSON response from {url}: {body}"
            ) from error

    def login(
        self,
        username: str,
        password: str,
        tenant_name: str = "",
        domain_name: str = "",
    ) -> None:
        payload = {
            "username": username,
            "password": password,
        }
        if tenant_name:
            payload["tenantName"] = tenant_name
        if domain_name:
            payload["domainName"] = domain_name

        response = self.request("POST", LOGIN_PATH, json=payload)
        token = first_value(
            response,
            (
                "token",
                "Token",
                "accessToken",
                "access_token",
                "data.token",
                "data.accessToken",
                "result.token",
                "result.accessToken",
            ),
        )

        if not token:
            raise RuntimeError(
                "Login succeeded but no token was found in the response:\n"
                + json.dumps(response, indent=2, default=str)[:3000]
            )

        self.session.headers.update(
            {
                "Token": str(token),
                "Authorization": f"Bearer {token}",
            }
        )
        print("Successfully authenticated")

    def get_devices(
        self,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_pages: int = DEFAULT_MAX_PAGES,
        page_param: str = "pageNo",
        page_size_param: str = "pageSize",
    ) -> List[Dict[str, Any]]:
        """Retrieve devices, following API pagination when available.

        The first request intentionally has no query parameters so it remains
        compatible with the working API call. If NetBrain returns pagination
        metadata, the next URL/token is followed. If metadata is absent and
        the page is full, a pageNo/pageSize request is attempted and duplicate
        records are detected to prevent an infinite loop.
        """
        all_devices: List[Dict[str, Any]] = []
        seen_devices: Set[Tuple[str, str, str]] = set()
        response = self.request("GET", DEVICES_PATH)
        page_number = 1

        for _ in range(max_pages):
            records = extract_records(
                response,
                ("devices", "data", "items", "results"),
            )
            page_devices = [
                item for item in records if isinstance(item, dict)
            ]

            new_count = 0
            for device in page_devices:
                key = device_key(device)
                if key not in seen_devices:
                    seen_devices.add(key)
                    all_devices.append(device)
                    new_count += 1

            print(
                f"Retrieved device page {page_number}: "
                f"{len(page_devices)} records ({new_count} new)"
            )

            # Some deployments ignore unknown page parameters and return the
            # first page repeatedly. Stop as soon as a later page adds no new
            # unique devices.
            if page_number > 1 and new_count == 0:
                print(
                    "Pagination returned no new unique devices; "
                    "stopping safely."
                )
                break

            next_url = find_first_key(
                response,
                {
                    "next",
                    "nexturl",
                    "nextpageurl",
                    "nextpageurl",
                    "nextlink",
                },
            )
            next_token = find_first_key(
                response,
                {
                    "nexttoken",
                    "nextpagetoken",
                    "continuationtoken",
                    "continuation_token",
                    "cursor",
                },
            )
            has_more = find_boolean_key(
                response,
                {"hasmore", "has_more", "ismore", "moreavailable"},
            )

            total = find_number_key(
                response,
                {"total", "totalcount", "total_count", "recordcount"},
            )
            if (
                has_more is None
                and total is not None
                and len(all_devices) < total
            ):
                has_more = True

            if next_url:
                response = self.request("GET", str(next_url))
                page_number += 1
                continue

            if next_token:
                response = self.request(
                    "GET",
                    DEVICES_PATH,
                    params={"pageToken": str(next_token)},
                )
                page_number += 1
                continue

            should_request_next_page = (
                has_more is True
                or (has_more is None and len(page_devices) >= page_size)
            )
            if not should_request_next_page:
                break

            page_number += 1
            try:
                response = self.request(
                    "GET",
                    DEVICES_PATH,
                    params={
                        page_param: page_number,
                        page_size_param: page_size,
                    },
                )
            except Exception as error:
                print(
                    f"Pagination request failed on page {page_number}: {error}"
                )
                break

            # If the server ignored the pagination parameters, the next page
            # will contain no new devices and the loop will stop safely.
            if page_number > 1 and not page_devices:
                break

        else:
            print(f"Stopped after --devices-max-pages {max_pages}")

        return all_devices

    def get_interfaces(
        self,
        device: Dict[str, Any],
        path_template: str,
        method: str = "GET",
    ) -> List[Dict[str, Any]]:
        device_id = first_value(
            device,
            ("id", "deviceId", "deviceID", "device_id", "uuid"),
        )
        if device_id is None:
            raise RuntimeError("Device has no ID: " + json.dumps(device)[:500])

        path = path_template.format(
            device_id=str(device_id),
            id=str(device_id),
            name=str(first_value(device, ("name", "hostName", "hostname"), "")),
        )
        response = self.request(method.upper(), path)
        interfaces = extract_records(
            response,
            ("interfaces", "ports", "data", "items", "results"),
        )
        return [item for item in interfaces if isinstance(item, dict)]


def first_value(
    obj: Any,
    paths: Iterable[str],
    default: Any = None,
) -> Any:
    for path in paths:
        value = obj
        found = True
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                found = False
                break
            value = value[part]
        if found and value not in (None, ""):
            return value
    return default


def extract_records(response: Any, preferred_keys: Iterable[str]) -> List[Any]:
    if isinstance(response, list):
        return response
    if not isinstance(response, dict):
        return []

    for key in preferred_keys:
        value = response.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            nested = extract_records(value, preferred_keys)
            if nested:
                return nested

    for key in ("result", "response", "payload"):
        value = response.get(key)
        if isinstance(value, (dict, list)):
            nested = extract_records(value, preferred_keys)
            if nested:
                return nested

    if response and all(isinstance(value, dict) for value in response.values()):
        return list(response.values())

    return []


def find_first_key(obj: Any, wanted_keys: Set[str]) -> Optional[Any]:
    """Find the first value for one of the keys at any response nesting level."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            normalized = re_key(key)
            if normalized in wanted_keys and value not in (None, "", False):
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
    if isinstance(obj, dict):
        for key, value in obj.items():
            if re_key(key) in wanted_keys and isinstance(value, bool):
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
        for nested_value in value.values():
            yield from flatten_strings(nested_value)
    elif isinstance(value, list):
        for nested_value in value:
            yield from flatten_strings(nested_value)
    elif value not in (None, ""):
        yield str(value)


def text_from(device: Dict[str, Any], names: Iterable[str]) -> str:
    values = []
    wanted = {re_key(name) for name in names}

    def collect(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if re_key(key) in wanted:
                    values.extend(flatten_strings(value))
                collect(value)
        elif isinstance(obj, list):
            for value in obj:
                collect(value)

    collect(device)
    return " ".join(values)


def is_ddc1_device(device: Dict[str, Any]) -> bool:
    # Search every nested value because the site may be under a nested
    # location/site object rather than a top-level siteName field.
    return "DDC1" in " ".join(flatten_strings(device)).upper()


def is_switch(device: Dict[str, Any]) -> bool:
    values = " ".join(flatten_strings(device)).lower()
    switch_terms = (
        "switch",
        "catalyst",
        "nexus",
        "n9k",
        "n3k",
        "n5k",
        "n7k",
        "arista",
        "eos",
        "nx-os",
        "nxos",
        "ios-xe",
        "leaf",
        "spine",
    )
    router_terms = (
        "router",
        "firewall",
        "load balancer",
        "wireless controller",
    )

    if any(term in values for term in router_terms) and "switch" not in values:
        return False
    return any(term in values for term in switch_terms)


def device_key(device: Dict[str, Any]) -> Tuple[str, str, str]:
    device_id = first_value(
        device,
        ("id", "deviceId", "deviceID", "device_id", "uuid"),
        "",
    )
    name = first_value(device, ("name", "deviceName", "hostName", "hostname"), "")
    ip = first_value(
        device,
        (
            "mgmtIP",
            "managementIp",
            "managementIP",
            "management_ip",
            "ip",
            "ipAddress",
        ),
        "",
    )
    return str(device_id), str(name).lower(), str(ip).lower()


def management_ip(device: Dict[str, Any]) -> str:
    return str(
        first_value(
            device,
            (
                "mgmtIP",
                "managementIp",
                "managementIP",
                "management_ip",
                "ip",
                "ipAddress",
            ),
            "",
        )
    )


def interface_value(interface: Dict[str, Any], names: Iterable[str]) -> str:
    value = first_value(interface, names, "")
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), default=str)
    return str(value)


def normalize_interface_row(
    device: Dict[str, Any], interface: Dict[str, Any]
) -> Dict[str, str]:
    return {
        "Device": str(first_value(device, ("name", "hostName", "hostname"), "")),
        "ManagementIP": management_ip(device),
        "DeviceType": str(
            first_value(device, ("subTypeName", "deviceType", "type"), "")
        ),
        "DeviceID": str(
            first_value(device, ("id", "deviceId", "deviceID", "uuid"), "")
        ),
        "Interface": interface_value(
            interface,
            (
                "name",
                "interfaceName",
                "ifName",
                "portName",
                "port",
                "displayName",
            ),
        ),
        "Description": interface_value(
            interface,
            ("description", "desc", "interfaceDescription"),
        ),
        "AdminStatus": interface_value(
            interface,
            ("adminStatus", "administrativeStatus", "admin_state"),
        ),
        "OperStatus": interface_value(
            interface,
            ("operStatus", "operationalStatus", "status", "linkStatus"),
        ),
        "Speed": interface_value(
            interface,
            ("speed", "bandwidth", "interfaceSpeed", "speedMbps"),
        ),
        "VLAN": interface_value(
            interface,
            ("vlan", "vlanId", "vlanID", "accessVlan", "nativeVlan"),
        ),
        "IPAddress": interface_value(
            interface,
            ("ipAddress", "ip", "ipv4Address", "ipv6Address"),
        ),
    }


def write_device_csv(devices: List[Dict[str, Any]], filename: str) -> None:
    fields = [
        "Name",
        "ManagementIP",
        "DeviceType",
        "DeviceID",
        "Site",
    ]
    with open(filename, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        for device in devices:
            writer.writerow({
                "Name": str(first_value(device, ("name", "deviceName", "hostName", "hostname"), "")),
                "ManagementIP": management_ip(device),
                "DeviceType": text_from(device, ("subTypeName", "deviceType", "type", "platform")),
                "DeviceID": str(first_value(device, ("id", "deviceId", "deviceID", "uuid"), "")),
                "Site": text_from(device, ("siteName", "site", "sitePath", "location", "locationName")),
            })


def display_devices(devices: List[Dict[str, Any]]) -> None:
    print("\n" + "=" * 120)
    print("DDC1 DEVICES")
    print("=" * 120)
    print(f"{'Device':<42}{'ManagementIP':<18}{'DeviceType':<30}{'Site':<30}")
    print("-" * 120)
    for device in devices:
        name = str(first_value(device, ("name", "deviceName", "hostName", "hostname"), ""))
        device_type = text_from(device, ("subTypeName", "deviceType", "type", "platform"))
        site = text_from(device, ("siteName", "site", "sitePath", "location", "locationName"))
        print(f"{name[:41]:<42}{management_ip(device)[:17]:<18}{device_type[:29]:<30}{site[:29]:<30}")


def write_csv(rows: List[Dict[str, str]], filename: str) -> None:
    fields = [
        "Device",
        "ManagementIP",
        "DeviceType",
        "DeviceID",
        "Interface",
        "Description",
        "AdminStatus",
        "OperStatus",
        "Speed",
        "VLAN",
        "IPAddress",
    ]
    with open(filename, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def display_rows(rows: List[Dict[str, str]]) -> None:
    headers = [
        ("Device", 38),
        ("ManagementIP", 16),
        ("Interface", 24),
        ("AdminStatus", 14),
        ("OperStatus", 14),
        ("Speed", 14),
        ("VLAN", 10),
        ("Description", 42),
    ]
    print("\n" + "=" * 180)
    print("DDC1 SWITCH INTERFACES")
    print("=" * 180)
    print("".join(f"{name:<{width}}" for name, width in headers))
    print("-" * 180)

    for row in rows:
        print(
            "".join(
                f"{row.get(name, '')[:width - 1]:<{width}}"
                for name, width in headers
            )
        )


def display_device_diagnostics(all_devices: List[Dict[str, Any]]) -> None:
    """Print enough schema information to identify NetBrain field names."""
    print("\nDEVICE FILTER DIAGNOSTIC")
    print("No DDC1 devices matched the returned records.")
    print(f"Records inspected: {len(all_devices)}")

    if not all_devices:
        print("No device schema was returned by the API.")
        return

    sample = all_devices[0]
    print("\nFirst device JSON sample:")
    print(json.dumps(sample, indent=2, default=str)[:10000])

    top_level_fields = sorted(str(key) for key in sample.keys())
    print("\nFirst device top-level fields:")
    print(", ".join(top_level_fields))

    print("\nFirst device nested field paths:")
    paths: List[str] = []

    def collect_paths(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, nested_value in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                paths.append(path)
                collect_paths(nested_value, path)
        elif isinstance(value, list) and value:
            collect_paths(value[0], f"{prefix}[]")

    collect_paths(sample)
    print(", ".join(paths[:300]))

    print("\nReturned device names/sites/types:")
    for device in all_devices[:20]:
        name = first_value(
            device,
            ("name", "deviceName", "hostName", "hostname"),
            "",
        )
        site = text_from(
            device,
            ("siteName", "site", "sitePath", "location", "locationName"),
        )
        device_type = text_from(
            device,
            (
                "subTypeName",
                "deviceType",
                "type",
                "deviceClass",
                "category",
                "platform",
            ),
        )
        print(f"  name={name!r}, site={site!r}, type={device_type!r}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Display all switch interfaces in DDC1 using the NetBrain R12 REST API."
        )
    )
    parser.add_argument(
        "--base-url",
        default="https://netbrain.mckesson.com",
        help="NetBrain R12 Application Server URL.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification.",
    )
    parser.add_argument(
        "--tenant-name",
        default="",
        help="Optional NetBrain tenant name sent during login.",
    )
    parser.add_argument(
        "--domain-name",
        default=DEFAULT_DOMAIN_NAME,
        help=(
            "NetBrain domain sent during login. Default: "
            f"{DEFAULT_DOMAIN_NAME}. Use --domain-name \"\" to omit it."
        ),
    )
    parser.add_argument(
        "--interfaces-path-template",
        default=DEFAULT_INTERFACES_PATH,
        help=(
            "Interface endpoint path template. Supported placeholders: "
            "{device_id}, {id}, and {name}."
        ),
    )
    parser.add_argument(
        "--interfaces-method",
        choices=("GET", "POST"),
        default="GET",
        help="HTTP method for the interface endpoint. Default: GET.",
    )
    parser.add_argument(
        "--devices-page-param",
        default="pageNo",
        help="Page-number query parameter used when metadata is absent.",
    )
    parser.add_argument(
        "--devices-page-size-param",
        default="pageSize",
        help="Page-size query parameter used when metadata is absent.",
    )
    parser.add_argument(
        "--devices-page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help=f"Expected page size for pagination. Default: {DEFAULT_PAGE_SIZE}.",
    )
    parser.add_argument(
        "--devices-max-pages",
        type=int,
        default=DEFAULT_MAX_PAGES,
        help=f"Maximum device pages to retrieve. Default: {DEFAULT_MAX_PAGES}.",
    )
    parser.add_argument(
        "--csv-file",
        default="ddc1_switch_interfaces.csv",
        help="CSV output filename for interface results.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.devices_page_size <= 0 or args.devices_max_pages <= 0:
        print(
            "Error: --devices-page-size and --devices-max-pages must be positive.",
            file=sys.stderr,
        )
        return 2

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    client = NetBrainClient(args.base_url, insecure=args.insecure)

    try:
        print("\nLogging into NetBrain...")
        client.login(
            username,
            password,
            tenant_name=args.tenant_name,
            domain_name=args.domain_name,
        )

        print("\nRetrieving devices...")
        all_devices = client.get_devices(
            page_size=args.devices_page_size,
            max_pages=args.devices_max_pages,
            page_param=args.devices_page_param,
            page_size_param=args.devices_page_size_param,
        )

        ddc1_devices = [device for device in all_devices if is_ddc1_device(device)]
        ddc1_switches = [device for device in ddc1_devices if is_switch(device)]

        print(f"\nTotal unique devices returned: {len(all_devices)}")
        print(f"DDC1 devices found: {len(ddc1_devices)}")
        print(f"DDC1 switches found: {len(ddc1_switches)}")

        if ddc1_devices:
            display_devices(ddc1_devices)
            device_csv = args.csv_file.rsplit(".", 1)[0] + "_devices.csv"
            write_device_csv(ddc1_devices, device_csv)
            print(f"Device inventory CSV saved to: {device_csv}")

        if not ddc1_devices:
            display_device_diagnostics(all_devices)
        elif not ddc1_switches:
            print("\nDDC1 devices were found, but none matched the switch filter.")
            print("DDC1 device types and names:")
            for device in ddc1_devices:
                name = first_value(
                    device,
                    ("name", "deviceName", "hostName", "hostname"),
                    "",
                )
                device_type = " ".join(flatten_strings(device)).strip()
                print(f"  {name}: {device_type[:300]}")

        rows: List[Dict[str, str]] = []
        for device in ddc1_devices:
            name = first_value(device, ("name", "hostName", "hostname"), "")
            try:
                interfaces = client.get_interfaces(
                    device,
                    args.interfaces_path_template,
                    args.interfaces_method,
                )
                if not interfaces:
                    print(f"{name}: no interfaces returned")
                for interface in interfaces:
                    rows.append(normalize_interface_row(device, interface))
                print(f"{name}: {len(interfaces)} interfaces")
            except Exception as error:
                print(f"{name}: interface lookup failed: {error}")

        rows.sort(key=lambda row: (row["Device"].lower(), row["Interface"].lower()))
        display_rows(rows)
        write_csv(rows, args.csv_file)
        print(f"\nCSV report saved to: {args.csv_file}")
        return 0

    except Exception as error:
        print(f"NetBrain query failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
