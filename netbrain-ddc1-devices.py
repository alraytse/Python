import csv
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Configuration ---
BASE_URL = "https://netbrain.mckesson.com"
API_PREFIX = f"{BASE_URL}/ServicesAPI/API/V1"

OUTPUT_FILE = (
    "/Users/alex.raytselsky/Downloads/ddc1_network_inventory.csv"
)

MAX_WORKERS = 50
PAGE_LIMIT = 100
MAX_ESTIMATED_PAGES = 100

DEFAULT_VRFS = {
    "default",
    "mgmt",
    "management",
    "global",
    "none",
    "null",
    "",
}

# --- Prompt for credentials ---
USERNAME = input("NetBrain username: ").strip()
PASSWORD = getpass.getpass("NetBrain password: ")

if not USERNAME or not PASSWORD:
    raise ValueError("Username and password are required.")

# --- Authenticate ---
login_url = f"{API_PREFIX}/Session"
login_payload = {
    "username": USERNAME,
    "password": PASSWORD,
}

print("Logging into NetBrain...")

response = requests.post(
    login_url,
    json=login_payload,
    verify=False,
    timeout=30,
)

if response.status_code != 200:
    raise Exception(
        f"Authentication failed ({response.status_code}): {response.text}"
    )

login_data = response.json()
token = login_data.get("token")

if not token:
    raise Exception("Token not found in login response payload.")

headers = {
    "Token": token,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

if login_data.get("tenantId") and login_data.get("domainId"):
    headers["tenantId"] = login_data["tenantId"]
    headers["domainId"] = login_data["domainId"]

def fetch_device_page(skip_value):
    url = f"{API_PREFIX}/CMDB/Devices"
    query_params = {
        "skip": skip_value,
        "limit": PAGE_LIMIT,
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=query_params,
            verify=False,
            timeout=30,
        )

        if response.status_code == 200:
            return response.json().get("devices", [])

    except Exception:
        pass

    return []

def enrich_device_metadata(device_id, hostname):
    interface_types = set()
    vrfs = set()
    protocols = set()

    query_params_id = (
        {"deviceId": device_id}
        if device_id
        else {"hostname": str(hostname).lower()}
    )

    query_params_fallback = {
        "hostname": str(hostname).lower()
    }

    try:
        interfaces_url = f"{API_PREFIX}/CMDB/Devices/Interfaces"

        response = requests.get(
            interfaces_url,
            headers=headers,
            params=query_params_id,
            verify=False,
            timeout=15,
        )

        if (
            response.status_code != 200
            or not response.json().get("interfaces")
        ):
            response = requests.get(
                interfaces_url,
                headers=headers,
                params=query_params_fallback,
                verify=False,
                timeout=15,
            )

        if response.status_code == 200:
            for interface in response.json().get("interfaces", []):
                interface_type = (
                    interface.get("interfaceType")
                    or interface.get("type")
                    or interface.get("intfType")
                )

                if interface_type:
                    interface_types.add(str(interface_type))

                vrf_name = (
                    interface.get("vrf")
                    or interface.get("vrfName")
                    or interface.get("vrf_name")
                )

                if (
                    vrf_name
                    and str(vrf_name).strip().lower() not in DEFAULT_VRFS
                ):
                    vrfs.add(str(vrf_name).strip())

    except Exception:
        pass

    try:
        protocols_url = (
            f"{API_PREFIX}/CMDB/Devices/Routing/Protocols"
        )

        response = requests.get(
            protocols_url,
            headers=headers,
            params=query_params_id,
            verify=False,
            timeout=15,
        )

        if (
            response.status_code != 200
            or not response.json().get("protocols")
        ):
            response = requests.get(
                protocols_url,
                headers=headers,
                params=query_params_fallback,
                verify=False,
                timeout=15,
            )

        if response.status_code == 200:
            for protocol in response.json().get("protocols", []):
                protocol_name = (
                    protocol.get("protocolName")
                    or protocol.get("name")
                    or protocol.get("type")
                )

                if protocol_name:
                    protocols.add(str(protocol_name).upper())

    except Exception:
        pass

    return list(interface_types), list(vrfs), list(protocols)

# --- Phase 1: Collect DDC1 devices ---
all_ddc1_devices = []
seen_hostnames = set()
all_discovered_columns = {
    "interfaceTypes",
    "vrfNames",
    "routingProtocols",
}

skip_offsets = [
    index * PAGE_LIMIT
    for index in range(MAX_ESTIMATED_PAGES)
]

print(f"Initializing {MAX_WORKERS} workers...")
print("Pulling inventory and compiling DDC1 device profiles...")

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    future_to_skip = {
        executor.submit(fetch_device_page, skip): skip
        for skip in skip_offsets
    }

    for future in as_completed(future_to_skip):
        try:
            devices_batch = future.result()

            for device in devices_batch:
                hostname = (
                    device.get("hostName")
                    or device.get("hostname")
                    or device.get("name")
                )

                if not hostname or hostname in seen_hostnames:
                    continue

                if "DDC1" not in str(device).upper():
                    continue

                seen_hostnames.add(hostname)

                flat_device = {
                    "_internal_processing_id": (
                        device.get("id")
                        or device.get("deviceId")
                    )
                }

                def is_excluded(field_name):
                    name_lower = field_name.lower()
                    return (
                        "id" in name_lower
                        or "discovery" in name_lower
                        or "time" in name_lower
                    )

                for key, value in device.items():
                    if key == "attributes" and isinstance(value, dict):
                        for sub_key, sub_value in value.items():
                            if not is_excluded(sub_key):
                                flat_device[f"attr_{sub_key}"] = sub_value
                    elif not is_excluded(key):
                        flat_device[key] = value

                for column in flat_device:
                    if column != "_internal_processing_id":
                        all_discovered_columns.add(column)

                all_ddc1_devices.append(flat_device)

        except Exception:
            pass

print(
    f"Phase 1 finished. Found "
    f"{len(all_ddc1_devices)} unique DDC1 devices."
)

# --- Phase 2: Enrich devices ---
if all_ddc1_devices:
    print("Gathering interface types, VRFs, and routing protocols...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_device = {}

        for device in all_ddc1_devices:
            hostname = (
                device.get("hostName")
                or device.get("hostname")
                or device.get("name")
            )

            device_id = device.get("_internal_processing_id")

            if hostname:
                future = executor.submit(
                    enrich_device_metadata,
                    device_id,
                    hostname,
                )
                future_to_device[future] = device

        for future in as_completed(future_to_device):
            device = future_to_device[future]

            try:
                interface_types, vrfs, protocols = future.result()

                device["interfaceTypes"] = (
                    ", ".join(sorted(interface_types))
                    if interface_types
                    else "N/A"
                )

                device["vrfNames"] = (
                    ", ".join(sorted(vrfs))
                    if vrfs
                    else "None"
                )

                device["routingProtocols"] = (
                    ", ".join(sorted(protocols))
                    if protocols
                    else "None"
                )

            except Exception:
                device["interfaceTypes"] = "Error"
                device["vrfNames"] = "Error"
                device["routingProtocols"] = "Error"

            finally:
                device.pop("_internal_processing_id", None)

# --- Generate CSV ---
if not all_ddc1_devices:
    all_ddc1_devices.append(
        {
            "hostName": "No Matching DDC1 Assets Discovered",
            "mgmtIP": "Verify NetBrain Scope Casing",
            "interfaceTypes": "N/A",
            "vrfNames": "None",
            "routingProtocols": "None",
        }
    )

    all_discovered_columns.update(
        {
            "hostName",
            "mgmtIP",
            "interfaceTypes",
            "vrfNames",
            "routingProtocols",
        }
    )

primary_headers = [
    "hostName",
    "hostname",
    "name",
    "mgmtIP",
    "mgmtIp",
    "managementIP",
    "interfaceTypes",
    "vrfNames",
    "routingProtocols",
]

dynamic_headers = [
    column
    for column in sorted(all_discovered_columns)
    if column not in primary_headers
]

ordered_headers = primary_headers + dynamic_headers

with open(
    OUTPUT_FILE,
    mode="w",
    newline="",
    encoding="utf-8",
) as csv_file:
    writer = csv.DictWriter(
        csv_file,
        fieldnames=ordered_headers,
        extrasaction="ignore",
    )

    writer.writeheader()
    writer.writerows(all_ddc1_devices)

print(f"Success! CSV generated at: {OUTPUT_FILE}")
print("Logging out...")

