import csv
import getpass
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

USERNAME = input("Enter NetBrain Username: ").strip()
PASSWORD = getpass.getpass("Enter NetBrain Password: ").strip()

if not USERNAME or not PASSWORD:
    sys.exit("Error: Username and Password cannot be empty.")

BASE_URL = "https://netbrain.mckesson.com/ServicesAPI/API/V1"
OUTPUT_FILE = os.path.expanduser("~/Downloads/ddc1_network_inventory.csv")

MAX_WORKERS = 10
PAGE_LIMIT = 100
MAX_ESTIMATED_PAGES = 100

session = requests.Session()
session.verify = False
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def authenticate() -> dict:
    login_url = f"{BASE_URL}/Session"
    login_payload = {"username": USERNAME, "password": PASSWORD}

    res = session.post(login_url, json=login_payload, timeout=15)
    if res.status_code != 200:
        raise RuntimeError(f"Auth failed ({res.status_code}): {res.text}")

    data = res.json()
    token = data.get("token")
    if not token:
        raise RuntimeError("Token missing in response payload.")

    session.headers.update(
        {
            "Token": token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )

    if data.get("tenantId") and data.get("domainId"):
        session.headers.update(
            {"tenantId": data.get("tenantId"), "domainId": data.get("domainId")}
        )

    return data


def fetch_device_page(skip_value: int) -> list:
    url = f"{BASE_URL}/CMDB/Devices"
    try:
        res = session.get(
            url, params={"skip": skip_value, "limit": PAGE_LIMIT}, timeout=30
        )
        return res.json().get("devices", []) if res.status_code == 200 else []
    except requests.RequestException:
        return []


def extract_interface_type(intf_name: str) -> str:
    if not intf_name:
        return ""
    match = re.match(r"^([a-zA-Z-]+)", str(intf_name).strip())
    if match:
        prefix = match.group(1).rstrip("-")
        if len(prefix) >= 2:
            return prefix
    return ""


def fetch_single_interface_attr(hostname: str, intf_name: str) -> tuple:
    url = f"{BASE_URL}/CMDB/Interfaces/Attributes"
    try:
        r = session.get(url, params={"hostname": hostname, "interfaceName": intf_name}, timeout=10)
        if r.status_code == 200:
            attrs = r.json().get("attributes", {}).get(intf_name, {})
            
            # Extract VRF
            vrf = attrs.get("mplsVrf", "").strip()
            
            # Extract IPs
            found_ips = []
            ips_raw = attrs.get("ips")
            if isinstance(ips_raw, list):
                for item in ips_raw:
                    if isinstance(item, dict) and item.get("ipLoc"):
                        found_ips.append(item["ipLoc"])
                    elif isinstance(item, str) and item.strip():
                        found_ips.append(item.strip())
            elif isinstance(ips_raw, str) and ips_raw.strip():
                found_ips.append(ips_raw.strip())
                
            return vrf, found_ips
    except requests.RequestException:
        pass
    return "", []


def enrich_device_metadata(hostname: str) -> tuple:
    types, vrfs, ip_addrs = set(), set(), set()

    if not hostname:
        return ["N/A"], ["default"], ["N/A"]

    # 1. Fetch Interface Names
    url = f"{BASE_URL}/CMDB/Interfaces"
    try:
        r = session.get(url, params={"hostname": hostname}, timeout=15)
        if r.status_code == 200:
            intf_names = r.json().get("interfaces", [])
            
            # Extract Interface Types from naming prefix
            for intf in intf_names:
                if_type = extract_interface_type(intf)
                if if_type:
                    types.add(if_type)

            # Fetch attributes for interfaces concurrently
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(fetch_single_interface_attr, hostname, intf): intf
                    for intf in intf_names
                }
                for future in as_completed(futures):
                    vrf, ips = future.result()
                    if vrf and vrf.lower() not in ["none", "null", "undefined", "n/a", "0"]:
                        vrfs.add(vrf)
                    for ip in ips:
                        ip_addrs.add(ip)

    except requests.RequestException:
        pass

    valid_vrfs = sorted(list(vrfs)) if vrfs else ["default"]
    return list(types), valid_vrfs, list(ip_addrs)


def main():
    authenticate()

    all_ddc1_devices = []
    seen_hostnames = set()
    all_discovered_columns = {
        "interfaceTypes",
        "vrfNames",
        "interfaceIPs",
    }
    skip_offsets = [i * PAGE_LIMIT for i in range(MAX_ESTIMATED_PAGES)]
    EXCLUDED_FIELDS = {"hostName", "hostname", "mgmtIP"}

    print(f"Fetching global CMDB devices ({MAX_WORKERS} workers)...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(fetch_device_page, skip): skip
            for skip in skip_offsets
        }

        for future in as_completed(futures):
            devices_batch = future.result()
            for device in devices_batch:
                hostname = (
                    device.get("hostName")
                    or device.get("hostname")
                    or device.get("name")
                )

                if hostname and hostname not in seen_hostnames:
                    searchable_fields = f"{hostname} {device.get('mgmtIP', '')} {device.get('subType', '')}".upper()

                    if "DDC1" in searchable_fields:
                        seen_hostnames.add(hostname)
                        flat_device = {"_raw_device": device}

                        for k, v in device.items():
                            if k in EXCLUDED_FIELDS or any(
                                ex in k.lower() for ex in ["id", "discovery", "time"]
                            ):
                                continue
                            if k == "attributes" and isinstance(v, dict):
                                for sub_k, sub_v in v.items():
                                    if sub_k not in EXCLUDED_FIELDS and not any(
                                        ex in sub_k.lower() for ex in ["id", "discovery", "time"]
                                    ):
                                        flat_device[f"attr_{sub_k}"] = sub_v
                            else:
                                flat_device[k] = v

                        all_discovered_columns.update(
                            k for k in flat_device if not k.startswith("_")
                        )
                        all_ddc1_devices.append(flat_device)

    print(f"Found {len(all_ddc1_devices)} DDC1 assets. Enriching interface & VRF metadata...")

    if all_ddc1_devices:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_map = {
                executor.submit(
                    enrich_device_metadata,
                    dev.get("name") or dev.get("hostName") or dev.get("hostname")
                ): dev
                for dev in all_ddc1_devices
            }

            for future in as_completed(future_map):
                dev = future_map[future]
                try:
                    types, vrfs, ips = future.result()
                    dev["interfaceTypes"] = ", ".join(sorted(types)) if types else "N/A"
                    dev["vrfNames"] = ", ".join(vrfs)
                    dev["interfaceIPs"] = ", ".join(sorted(ips)) if ips else "N/A"
                except Exception:
                    dev["interfaceTypes"] = "N/A"
                    dev["vrfNames"] = "default"
                    dev["interfaceIPs"] = "N/A"
                finally:
                    dev.pop("_raw_device", None)

    if not all_ddc1_devices:
        all_ddc1_devices.append(
            {
                "name": "No Matching DDC1 Assets Discovered",
                "interfaceIPs": "N/A",
                "interfaceTypes": "N/A",
                "vrfNames": "default",
            }
        )

    primary_headers = ["name", "interfaceIPs", "interfaceTypes", "vrfNames"]
    extra_headers = sorted(
        [
            col
            for col in all_discovered_columns
            if col not in primary_headers and col not in EXCLUDED_FIELDS
        ]
    )
    ordered_headers = primary_headers + extra_headers

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file, fieldnames=ordered_headers, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(all_ddc1_devices)

    print(f"Export successful: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()