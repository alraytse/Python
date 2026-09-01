#!/usr/bin/env python3

import argparse
import csv
import getpass
import json
import sys
from typing import Any, Dict, Iterable, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGIN_PATH = "/ServicesAPI/API/V1/Session"
DEVICES_PATH = "/ServicesAPI/API/V1/CMDB/Devices"
DEFAULT_INTERFACES_PATH = (
    "/ServicesAPI/API/V1/CMDB/Devices/{device_id}/Interfaces"
)


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
        url = path if path.startswith("http") else self.base_url + path
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

    def get_devices(self) -> List[Dict[str, Any]]:
        response = self.request("GET", DEVICES_PATH)
        devices = extract_records(response, ("devices", "data", "items", "results"))
        return [item for item in devices if isinstance(item, dict)]

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


def text_from(device: Dict[str, Any], names: Iterable[str]) -> str:
    values = []
    for name in names:
        value = device.get(name)
        if value not in (None, ""):
            values.append(str(value))
    return " ".join(values)


def is_ddc1_device(device: Dict[str, Any]) -> bool:
    values = text_from(
        device,
        (
            "name",
            "hostName",
            "hostname",
            "siteName",
            "site",
            "sitePath",
            "mgmtIP",
            "managementIp",
            "managementIP",
        ),
    )
    return "DDC1" in values.upper()


def is_switch(device: Dict[str, Any]) -> bool:
    values = text_from(
        device,
        (
            "subTypeName",
            "deviceType",
            "type",
            "deviceClass",
            "category",
            "vendor",
            "model",
            "platform",
            "name",
        ),
    ).lower()

    switch_terms = (
        "switch",
        "catalyst",
        "nexus",
        "n9k",
        "n3k",
        "n5k",
        "n7k",
        "nexus",
        "arista",
        "eos",
    )
    router_terms = ("router", "firewall", "load balancer", "wireless controller")

    if any(term in values for term in router_terms) and "switch" not in values:
        return False
    return any(term in values for term in switch_terms)


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
        default="",
        help="Optional NetBrain domain name sent during login.",
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
        "--csv-file",
        default="ddc1_switch_interfaces.csv",
        help="CSV output filename.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
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
        all_devices = client.get_devices()
        ddc1_switches = [
            device
            for device in all_devices
            if is_ddc1_device(device) and is_switch(device)
        ]

        print(f"Total devices returned: {len(all_devices)}")
        print(f"DDC1 switches found: {len(ddc1_switches)}")

        rows: List[Dict[str, str]] = []
        for device in ddc1_switches:
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
