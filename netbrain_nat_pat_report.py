#!/usr/bin/env python3
"""
NetBrain R12 configured NAT/PAT rule report.

The script logs into NetBrain, retrieves devices from CMDB, downloads each
configured device configuration, extracts configured NAT/PAT rules, and writes
an audit-friendly CSV report. It does not retrieve live NAT translations and
it does not make configuration changes.

Dependencies:
    pip install requests

Example:
    python3 netbrain_nat_pat_report.py \
        --base-url https://netbrain.mckesson.com \
        --insecure \
        --site-name DDC1 \
        --csv-file nat_pat_rules.csv

The configuration endpoint is deployment/version dependent. If the default
path is not valid in your R12 instance, override it with --config-path-template.
Supported placeholders are {device_id}, {device_name}, and {management_ip}.
"""

import argparse
import csv
import getpass
import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_BASE_URL = "https://netbrain.mckesson.com"
LOGIN_PATH = "/ServicesAPI/API/V1/Session"
DEVICES_PATH = "/ServicesAPI/API/V1/CMDB/Devices"
DEFAULT_CONFIG_PATH_TEMPLATE = (
    "/ServicesAPI/API/V1/CMDB/Devices/{device_id}/Configuration"
)
DEFAULT_CSV_FILE = "netbrain_nat_pat_rules.csv"
DEFAULT_TIMEOUT = 90
DEFAULT_PAGE_SIZE = 50
DEFAULT_MAX_PAGES = 200

IP_PATTERN = re.compile(
    r"(?<![0-9])"
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\."
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\."
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\."
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
    r"(?![0-9])"
)

DEVICE_NAME_KEYS = (
    "name",
    "deviceName",
    "hostname",
    "hostName",
    "displayName",
)
DEVICE_ID_KEYS = (
    "id",
    "deviceId",
    "deviceID",
    "entityId",
    "entityID",
    "uuid",
)
DEVICE_IP_KEYS = (
    "mgmtIP",
    "managementIP",
    "managementIp",
    "management_ip",
    "managementAddress",
    "ipAddress",
    "ip",
)
DEVICE_TYPE_KEYS = (
    "subTypeName",
    "assetType",
    "deviceType",
    "deviceClass",
    "type",
    "category",
    "platform",
    "role",
    "vendor",
    "model",
)
DEVICE_SITE_KEYS = (
    "siteName",
    "site",
    "sitePath",
    "location",
    "locationName",
    "containerName",
)

CSV_FIELDS = [
    "Device",
    "Management_IP",
    "Device_Type",
    "Device_ID",
    "Site",
    "Rule_Type",
    "Source_IP",
    "Source_Port",
    "Public_Global_IP",
    "Public_Port",
    "Translated_IP",
    "Translated_Port",
    "Destination_IP",
    "Destination_Port",
    "Protocol",
    "Inside_Interface",
    "Outside_Interface",
    "VRF_Context",
    "Assignment",
    "Rule_Text",
    "Collection_Status",
    "Error",
]


def clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), default=str)
    return str(value).strip()


def normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def first_value(
    obj: Any,
    keys: Iterable[str],
    default: Any = "",
) -> Any:
    if not isinstance(obj, dict):
        return default

    normalized_obj = {
        normalized_key(key): value for key, value in obj.items()
    }
    for key in keys:
        value = normalized_obj.get(normalized_key(key), "")
        if value not in (None, "", []):
            return value
    return default


def nested_first_value(
    obj: Any,
    paths: Iterable[str],
    default: Any = "",
) -> Any:
    for path in paths:
        value = obj
        found = True
        for part in path.split("."):
            if not isinstance(value, dict):
                found = False
                break
            value = next(
                (
                    candidate
                    for key, candidate in value.items()
                    if normalized_key(key) == normalized_key(part)
                ),
                None,
            )
            if value is None:
                found = False
                break
        if found and value not in (None, "", []):
            return value
    return default


def extract_records(
    payload: Any,
    preferred_keys: Sequence[str],
) -> List[Dict[str, Any]]:
    """Extract records from common NetBrain response envelopes."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []

    preferred = {normalized_key(key) for key in preferred_keys}
    for key, value in payload.items():
        if normalized_key(key) in preferred:
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                nested = extract_records(value, preferred_keys)
                if nested:
                    return nested

    for key in (
        "data",
        "result",
        "results",
        "response",
        "payload",
        "items",
        "records",
        "devices",
        "configuration",
        "config",
    ):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = extract_records(value, preferred_keys)
            if nested:
                return nested

    return []


def find_token(payload: Any) -> str:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if normalized_key(key) in {
                "token",
                "accesstoken",
                "sessiontoken",
                "jwt",
            } and value:
                return clean(value)
        for value in payload.values():
            token = find_token(value)
            if token:
                return token
    elif isinstance(payload, list):
        for value in payload:
            token = find_token(value)
            if token:
                return token
    return ""


def recursive_strings(payload: Any, path: str = "") -> Iterable[Tuple[str, str]]:
    if isinstance(payload, str):
        yield path, payload
    elif isinstance(payload, dict):
        for key, value in payload.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from recursive_strings(value, child_path)
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            yield from recursive_strings(value, f"{path}[{index}]")


def extract_configuration_text(payload: Any) -> str:
    """Return the most likely configuration text from an API response."""
    candidates: List[Tuple[int, str, str]] = []
    preferred_terms = (
        "configuration",
        "runningconfig",
        "startupconfig",
        "configtext",
        "rawconfig",
        "content",
        "text",
        "config",
        "running",
    )

    for path, value in recursive_strings(payload):
        text = value.strip()
        if len(text) < 10:
            continue
        lower_path = path.lower().replace("_", "")
        score = len(text)
        if any(term in lower_path for term in preferred_terms):
            score += 1_000_000
        if re.search(
            r"(?im)^\s*(?:ip nat|nat\s*\(|set .*nat|config firewall vip|object network|ltm virtual)",
            text,
        ):
            score += 500_000
        candidates.append((score, path, text))

    if not candidates:
        return ""
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][2]


def normalize_device(record: Dict[str, Any]) -> Dict[str, str]:
    return {
        "id": clean(first_value(record, DEVICE_ID_KEYS)),
        "name": clean(first_value(record, DEVICE_NAME_KEYS)),
        "management_ip": clean(first_value(record, DEVICE_IP_KEYS)),
        "device_type": clean(first_value(record, DEVICE_TYPE_KEYS)),
        "site": clean(first_value(record, DEVICE_SITE_KEYS)),
        "raw": record,
    }


def device_key(device: Dict[str, str]) -> str:
    return (
        device.get("id")
        or device.get("management_ip")
        or device.get("name")
    ).strip().lower()


def deduplicate_devices(
    devices: Iterable[Dict[str, str]],
) -> List[Dict[str, str]]:
    unique: Dict[str, Dict[str, str]] = {}
    for device in devices:
        key = device_key(device)
        if key and key not in unique:
            unique[key] = device
    return list(unique.values())


def device_search_text(device: Dict[str, str]) -> str:
    raw = device.get("raw", {})
    values = [
        device.get("name", ""),
        device.get("management_ip", ""),
        device.get("device_type", ""),
        device.get("site", ""),
    ]
    if isinstance(raw, dict):
        values.extend(clean(value) for value in raw.values())
    return " ".join(values)


def classify_assignment(text: str) -> str:
    upper = text.upper()
    has_mt = bool(re.search(r"\bMT\b|\bMT[-_ ]", upper))
    has_uson = bool(re.search(r"\bUSON\b|\bUSO\b", upper))
    if has_mt and has_uson:
        return "MT/USON - REVIEW"
    if has_mt:
        return "MT"
    if has_uson:
        return "USON"
    return "UNKNOWN"


def extract_ips(text: str) -> List[str]:
    return list(dict.fromkeys(IP_PATTERN.findall(text)))


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_port(value: str) -> bool:
    return value.isdigit() and 0 < int(value) <= 65535


def ip_port_pairs(text: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for match in IP_PATTERN.finditer(text):
        after = text[match.end():]
        port_match = re.match(r"\s+(\d{1,5})\b", after)
        port = port_match.group(1) if port_match and is_port(port_match.group(1)) else ""
        pairs.append((match.group(0), port))
    return pairs


def make_row(
    device: Dict[str, str],
    rule_type: str,
    rule_text: str,
    **values: str,
) -> Dict[str, str]:
    searchable = " ".join(
        [
            device_search_text(device),
            rule_text,
            values.get("Source_IP", ""),
            values.get("Public_Global_IP", ""),
            values.get("Translated_IP", ""),
        ]
    )
    row = {field: "" for field in CSV_FIELDS}
    row.update(
        {
            "Device": device.get("name", ""),
            "Management_IP": device.get("management_ip", ""),
            "Device_Type": device.get("device_type", ""),
            "Device_ID": device.get("id", ""),
            "Site": device.get("site", ""),
            "Rule_Type": rule_type,
            "Rule_Text": rule_text.strip(),
            "Assignment": classify_assignment(searchable),
            "Collection_Status": "SUCCESS",
        }
    )
    for key, value in values.items():
        if key in row:
            row[key] = clean(value)
    return row


def parse_cisco_line(device: Dict[str, str], line: str) -> Optional[Dict[str, str]]:
    stripped = line.strip()
    lower = stripped.lower()
    if not lower.startswith("ip nat "):
        return None

    ips = extract_ips(stripped)
    pairs = ip_port_pairs(stripped)
    ports = [port for _, port in pairs if port]
    rule_type = "PAT" if re.search(
        r"\b(?:tcp|udp|overload|service)\b", lower
    ) else "NAT"

    source_ip = ""
    public_ip = ""
    translated_ip = ""
    if " static " in f" {lower} ":
        if len(ips) >= 2:
            source_ip, public_ip = ips[0], ips[1]
            translated_ip = source_ip
        elif len(ips) == 1:
            public_ip = ips[0]
    elif " pool " in f" {lower} ":
        translated_ip = ips[0] if ips else ""
    elif " interface " in f" {lower} ":
        public_ip = "interface"
    elif ips:
        source_ip = ips[0]
        public_ip = ips[-1] if len(ips) > 1 else ""

    protocol_match = re.search(r"\b(tcp|udp|icmp)\b", lower)
    interface_match = re.search(
        r"\binterface\s+(\S+)", stripped, re.IGNORECASE
    )
    return make_row(
        device,
        rule_type,
        stripped,
        Source_IP=source_ip,
        Source_Port=ports[0] if ports else "",
        Public_Global_IP=public_ip,
        Public_Port=ports[-1] if len(ports) > 1 else "",
        Translated_IP=translated_ip,
        Translated_Port=ports[0] if ports else "",
        Protocol=protocol_match.group(1).upper() if protocol_match else "",
        Inside_Interface="inside" if "inside" in lower else "",
        Outside_Interface=interface_match.group(1) if interface_match else (
            "outside" if "outside" in lower else ""
        ),
    )


def parse_asa_configuration(
    device: Dict[str, str],
    lines: Sequence[str],
) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    object_name = ""
    object_host = ""

    for line in lines:
        stripped = line.strip()
        lower = stripped.lower()
        if not stripped or stripped.startswith("!"):
            continue

        object_match = re.match(r"object\s+network\s+(.+)", stripped, re.I)
        if object_match:
            object_name = object_match.group(1).strip().strip('"')
            object_host = ""
            continue

        host_match = re.match(r"host\s+(\S+)", stripped, re.I)
        if object_name and host_match and valid_ip(host_match.group(1)):
            object_host = host_match.group(1)
            continue

        if not lower.startswith("nat ") and not lower.startswith("nat("):
            continue

        ips = extract_ips(stripped)
        pairs = ip_port_pairs(stripped)
        ports = [port for _, port in pairs if port]
        service_match = re.search(
            r"service\s+(tcp|udp)\s+(\d+)\s+(\d+)",
            stripped,
            re.I,
        )
        is_dynamic = " dynamic " in f" {lower} "
        is_static = " static " in f" {lower} "
        rule_type = "PAT" if service_match or is_dynamic else "NAT"

        source_ip = object_host
        public_ip = ""
        translated_ip = object_host
        if is_static and ips:
            public_ip = ips[0]
        elif is_dynamic and ips:
            public_ip = ips[0]
            translated_ip = "dynamic"
        elif "interface" in lower:
            public_ip = "interface"
            translated_ip = "dynamic"

        rows.append(
            make_row(
                device,
                rule_type,
                stripped,
                Source_IP=source_ip,
                Source_Port=service_match.group(2) if service_match else "",
                Public_Global_IP=public_ip,
                Public_Port=service_match.group(3) if service_match else "",
                Translated_IP=translated_ip,
                Translated_Port=service_match.group(2) if service_match else "",
                Protocol=service_match.group(1).upper() if service_match else "",
                Inside_Interface=(
                    re.search(r"nat\s*\(([^,]+),", stripped, re.I).group(1)
                    if re.search(r"nat\s*\(([^,]+),", stripped, re.I)
                    else ""
                ),
                Outside_Interface=(
                    re.search(r"nat\s*\([^,]+,([^\)]+)\)", stripped, re.I).group(1)
                    if re.search(r"nat\s*\([^,]+,([^\)]+)\)", stripped, re.I)
                    else ""
                ),
                VRF_Context=object_name,
            )
        )
    return rows


def parse_fortigate_vips(
    device: Dict[str, str],
    lines: Sequence[str],
) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    in_vip_block = False
    current: Dict[str, str] = {}

    def emit() -> None:
        if not current.get("extip") and not current.get("mappedip"):
            return
        extip = current.get("extip", "")
        mappedip = current.get("mappedip", "")
        rule_type = "PAT" if current.get("portforward") == "enable" else "NAT"
        rows.append(
            make_row(
                device,
                rule_type,
                current.get("rule_text", ""),
                Public_Global_IP=extip,
                Public_Port=current.get("extport", ""),
                Translated_IP=mappedip,
                Translated_Port=current.get("mappedport", ""),
                Protocol=current.get("protocol", "").upper(),
                Outside_Interface=current.get("extintf", ""),
                VRF_Context=current.get("name", ""),
            )
        )

    for line in lines:
        stripped = line.strip()
        lower = stripped.lower()
        if lower == "config firewall vip":
            in_vip_block = True
            current = {}
            continue
        if not in_vip_block:
            continue
        if lower.startswith("edit "):
            if current:
                emit()
            current = {"name": stripped[5:].strip().strip('"')}
        elif lower == "next":
            emit()
            current = {}
        elif lower == "end":
            if current:
                emit()
            in_vip_block = False
            current = {}
        elif lower.startswith("set "):
            parts = stripped.split(None, 2)
            if len(parts) >= 3:
                key, value = parts[1].lower(), parts[2].strip().strip('"')
                current[key] = value
                current.setdefault("rule_text", "")
                current["rule_text"] += f" {stripped}"
    return rows


def parse_palo_alto_line(
    device: Dict[str, str],
    line: str,
) -> Optional[Dict[str, str]]:
    stripped = line.strip()
    lower = stripped.lower()
    if not lower.startswith("set ") or " nat " not in f" {lower} ":
        return None

    ips = extract_ips(stripped)
    ports = [port for _, port in ip_port_pairs(stripped) if port]
    rule_type = "PAT" if any(
        token in lower
        for token in (
            "dynamic-ip-and-port",
            "source-translation",
            "translated-port",
        )
    ) else "NAT"
    protocol_match = re.search(r"\b(tcp|udp)\b", lower)
    translated_address_match = re.search(
        r"translated-address\s+(\S+)", stripped, re.I
    )
    translated_address = (
        translated_address_match.group(1)
        if translated_address_match
        else (ips[-1] if ips else "")
    )
    return make_row(
        device,
        rule_type,
        stripped,
        Public_Global_IP=ips[0] if ips else "",
        Public_Port=ports[-1] if ports else "",
        Translated_IP=translated_address,
        Translated_Port=ports[-1] if "translated-port" in lower and ports else "",
        Protocol=protocol_match.group(1).upper() if protocol_match else "",
        VRF_Context="Palo Alto rulebase nat rule",
    )


def parse_generic_nat_line(
    device: Dict[str, str],
    line: str,
) -> Optional[Dict[str, str]]:
    stripped = line.strip()
    lower = stripped.lower()
    if not re.search(
        r"\b(?:nat|pat|snat|dnat|vip|virtual-server|source-translation|destination-translation)\b",
        lower,
    ):
        return None
    if not extract_ips(stripped) and not re.search(
        r"\b(?:vip|nat|pat|snat|dnat)\b", lower
    ):
        return None

    ips = extract_ips(stripped)
    ports = [port for _, port in ip_port_pairs(stripped) if port]
    rule_type = "PAT" if re.search(
        r"\b(?:pat|overload|portforward|port-forward|source-translation|service)\b",
        lower,
    ) else "NAT"
    protocol_match = re.search(r"\b(tcp|udp|icmp)\b", lower)
    return make_row(
        device,
        rule_type,
        stripped,
        Source_IP=ips[0] if ips else "",
        Source_Port=ports[0] if ports else "",
        Public_Global_IP=ips[1] if len(ips) > 1 else (ips[0] if ips else ""),
        Public_Port=ports[-1] if len(ports) > 1 else "",
        Translated_IP=ips[-1] if ips else "",
        Translated_Port=ports[0] if ports else "",
        Protocol=protocol_match.group(1).upper() if protocol_match else "",
    )


def parse_configuration(
    device: Dict[str, str],
    configuration: str,
) -> List[Dict[str, str]]:
    lines = configuration.splitlines()
    rows: List[Dict[str, str]] = []

    asa_rows = parse_asa_configuration(device, lines)
    rows.extend(asa_rows)
    rows.extend(parse_fortigate_vips(device, lines))
    asa_rule_texts = {row["Rule_Text"] for row in asa_rows}

    for line in lines:
        if not line.strip():
            continue
        if line.strip() in asa_rule_texts:
            continue
        cisco_row = parse_cisco_line(device, line)
        if cisco_row:
            rows.append(cisco_row)
            continue
        palo_row = parse_palo_alto_line(device, line)
        if palo_row:
            rows.append(palo_row)
            continue
        generic_row = parse_generic_nat_line(device, line)
        if generic_row:
            rows.append(generic_row)

    unique: Dict[Tuple[str, str], Dict[str, str]] = {}
    for row in rows:
        key = (row["Device"], row["Rule_Text"])
        unique[key] = row
    return list(unique.values())


def build_path(template: str, device: Dict[str, str]) -> str:
    values = {
        "device_id": quote(device.get("id", ""), safe=""),
        "device_name": quote(device.get("name", ""), safe=""),
        "management_ip": quote(device.get("management_ip", ""), safe=""),
    }
    try:
        return template.format(**values)
    except KeyError as error:
        raise ValueError(
            f"Unsupported path placeholder {{{error.args[0]}}}; use "
            "{device_id}, {device_name}, or {management_ip}."
        ) from error


class NetBrainClient:
    def __init__(self, args: argparse.Namespace, username: str, password: str):
        self.base_url = args.base_url.rstrip("/")
        self.timeout = args.timeout
        self.page_size = args.page_size
        self.max_pages = args.max_pages
        self.site_name = args.site_name.strip()
        self.config_path_template = args.config_path_template
        self.config_method = args.config_method.upper()
        self.tenant_name = args.tenant_name.strip()
        self.domain_name = args.domain_name.strip()
        self.session = requests.Session()
        self.session.verify = not args.insecure
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        self.username = username
        self.password = password

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = path if path.startswith("http") else self.base_url + path
        response = self.session.request(
            method=method.upper(),
            url=url,
            params=params,
            json=json_body,
            timeout=self.timeout,
        )
        if not response.ok:
            detail = response.text[:1000].replace("\n", " ")
            raise RuntimeError(
                f"HTTP {response.status_code} from {method.upper()} {url}: {detail}"
            )
        if not response.text.strip():
            return {}
        try:
            return response.json()
        except ValueError as error:
            detail = response.text[:1000].replace("\n", " ")
            if "html" in response.headers.get("Content-Type", "").lower():
                raise RuntimeError(
                    f"NetBrain returned HTML instead of JSON from {url}. "
                    "Verify the R12 Application Server URL and API path."
                ) from error
            raise RuntimeError(
                f"Non-JSON response from {url}: {detail}"
            ) from error

    def login(self) -> None:
        payload: Dict[str, Any] = {
            "username": self.username,
            "password": self.password,
        }
        if self.tenant_name:
            payload["tenantName"] = self.tenant_name
        if self.domain_name:
            payload["domainName"] = self.domain_name

        response = self.request("POST", LOGIN_PATH, json_body=payload)
        token = find_token(response)
        if not token:
            raise RuntimeError(
                "Login returned no session token:\n"
                + json.dumps(response, indent=2, default=str)[:3000]
            )
        self.session.headers.update(
            {
                "Token": token,
                "Authorization": f"Bearer {token}",
            }
        )

    def get_devices(self) -> List[Dict[str, str]]:
        all_devices: List[Dict[str, str]] = []
        previous_unique_count = -1

        for page in range(1, self.max_pages + 1):
            params = {
                "page": page,
                "pageNo": page,
                "pageSize": self.page_size,
                "limit": self.page_size,
            }
            if self.site_name:
                params["siteName"] = self.site_name

            response = self.request("GET", DEVICES_PATH, params=params)
            records = extract_records(
                response,
                ("devices", "items", "records", "data", "results"),
            )
            all_devices.extend(normalize_device(record) for record in records)
            unique_devices = deduplicate_devices(all_devices)

            if not records:
                break
            if len(unique_devices) == previous_unique_count:
                break
            previous_unique_count = len(unique_devices)
            if len(records) < self.page_size:
                break

        devices = deduplicate_devices(all_devices)
        if self.site_name:
            site_lower = self.site_name.lower()
            devices = [
                device
                for device in devices
                if not device.get("site")
                or site_lower in device.get("site", "").lower()
                or site_lower in device_search_text(device).lower()
            ]
        return devices

    def get_configuration(self, device: Dict[str, str]) -> str:
        path = build_path(self.config_path_template, device)
        params = {
            "deviceId": device.get("id", ""),
            "deviceName": device.get("name", ""),
            "managementIP": device.get("management_ip", ""),
        }
        body = dict(params)
        response = self.request(
            self.config_method,
            path,
            params=params if self.config_method == "GET" else None,
            json_body=body if self.config_method != "GET" else None,
        )
        return extract_configuration_text(response)


def empty_row(
    device: Dict[str, str],
    status: str,
    error: str = "",
) -> Dict[str, str]:
    row = {field: "" for field in CSV_FIELDS}
    row.update(
        {
            "Device": device.get("name", ""),
            "Management_IP": device.get("management_ip", ""),
            "Device_Type": device.get("device_type", ""),
            "Device_ID": device.get("id", ""),
            "Site": device.get("site", ""),
            "Assignment": classify_assignment(device_search_text(device)),
            "Collection_Status": status,
            "Error": error,
        }
    )
    return row


def collect_device(
    client: NetBrainClient,
    device: Dict[str, str],
) -> List[Dict[str, str]]:
    try:
        configuration = client.get_configuration(device)
        if not configuration:
            return [empty_row(device, "NO_CONFIGURATION_RETURNED")]
        rules = parse_configuration(device, configuration)
        if not rules:
            return [empty_row(device, "NO_NAT_RULES_FOUND")]
        return rules
    except Exception as error:
        return [empty_row(device, "FAILED", str(error))]


def write_csv(rows: Sequence[Dict[str, str]], filename: str) -> None:
    with Path(filename).open(
        "w", newline="", encoding="utf-8"
    ) as output_file:
        writer = csv.DictWriter(output_file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def display_rows(rows: Sequence[Dict[str, str]]) -> None:
    headers = [
        ("Device", 30),
        ("Type", 18),
        ("Rule", 8),
        ("Source_IP", 16),
        ("Public_IP", 16),
        ("Translated_IP", 16),
        ("Ports", 13),
        ("Assignment", 16),
        ("Status", 24),
    ]
    print("\n" + "=" * 175)
    print("NETBRAIN CONFIGURED NAT/PAT RULE REPORT")
    print("=" * 175)
    print("".join(f"{name:<{width}}" for name, width in headers))
    print("-" * 175)

    for row in rows:
        ports = "/".join(
            value
            for value in (
                row.get("Source_Port", ""),
                row.get("Public_Port", ""),
                row.get("Translated_Port", ""),
            )
            if value
        )
        values = {
            "Device": row.get("Device", ""),
            "Type": row.get("Device_Type", ""),
            "Rule": row.get("Rule_Type", ""),
            "Source_IP": row.get("Source_IP", ""),
            "Public_IP": row.get("Public_Global_IP", ""),
            "Translated_IP": row.get("Translated_IP", ""),
            "Ports": ports,
            "Assignment": row.get("Assignment", ""),
            "Status": row.get("Collection_Status", ""),
        }
        print(
            "".join(
                f"{values[name][:width - 1]:<{width}}"
                for name, width in headers
            )
        )
        if row.get("Error"):
            print(f"  Error: {row['Error']}")
        if row.get("Rule_Text"):
            print(f"  Rule: {row['Rule_Text']}")

    print("\n" + "=" * 175)
    print(f"Report rows       : {len(rows)}")
    print(f"Configured rules  : {sum(1 for row in rows if row['Rule_Type'])}")
    print(f"Failed devices    : {sum(1 for row in rows if row['Collection_Status'] == 'FAILED')}")
    print("=" * 175)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Report configured NAT/PAT rules from NetBrain R12 device "
            "configurations. No live translations or config changes."
        )
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"NetBrain R12 Application Server URL. Default: {DEFAULT_BASE_URL}",
    )
    parser.add_argument(
        "--site-name",
        default="",
        help="Optional site filter, such as DDC1. Blank queries all CMDB devices.",
    )
    parser.add_argument(
        "--tenant-name",
        default="",
        help="Optional tenant name sent during login.",
    )
    parser.add_argument(
        "--domain-name",
        default="",
        help="Optional domain name sent during login.",
    )
    parser.add_argument(
        "--config-path-template",
        default=DEFAULT_CONFIG_PATH_TEMPLATE,
        help=(
            "Configuration endpoint template. Supported placeholders: "
            "{device_id}, {device_name}, {management_ip}."
        ),
    )
    parser.add_argument(
        "--config-method",
        choices=("GET", "POST"),
        default="GET",
        help="HTTP method for the configuration endpoint. Default: GET.",
    )
    parser.add_argument(
        "--csv-file",
        default=DEFAULT_CSV_FILE,
        help=f"CSV output file. Default: {DEFAULT_CSV_FILE}",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help=f"Requested CMDB page size. Default: {DEFAULT_PAGE_SIZE}",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=DEFAULT_MAX_PAGES,
        help=f"Maximum CMDB pages. Default: {DEFAULT_MAX_PAGES}",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds. Default: {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for internal endpoints.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.page_size < 1 or args.max_pages < 1 or args.timeout < 1:
        print("Error: page-size, max-pages, and timeout must be positive.", file=sys.stderr)
        return 2

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    client = NetBrainClient(args, username, password)

    try:
        print("\nLogging into NetBrain...")
        client.login()
        print("Successfully authenticated.")

        scope = args.site_name or "all CMDB devices"
        print(f"Retrieving devices from {scope}...")
        devices = client.get_devices()
        print(f"Unique devices found: {len(devices)}")
        if not devices:
            print("No devices were returned. Verify permissions, filters, and CMDB pagination.")
            return 1

        rows: List[Dict[str, str]] = []
        for index, device in enumerate(devices, start=1):
            label = device.get("name") or device.get("management_ip") or device.get("id")
            print(f"[{index}/{len(devices)}] Collecting configuration from {label}...")
            device_rows = collect_device(client, device)
            rows.extend(device_rows)
            status = device_rows[0].get("Collection_Status", "")
            rule_count = sum(1 for row in device_rows if row.get("Rule_Type"))
            print(f"  {status}; configured NAT/PAT rules: {rule_count}")

        rows.sort(
            key=lambda row: (
                row.get("Device", "").lower(),
                row.get("Rule_Text", "").lower(),
            )
        )
        write_csv(rows, args.csv_file)
        display_rows(rows)
        print(f"\nCSV report saved to: {args.csv_file}")
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"NetBrain query failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
