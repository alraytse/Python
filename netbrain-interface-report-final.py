import csv
import getpass
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3

# Disable insecure HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Interactive Inputs & Configuration
# ---------------------------------------------------------------------------
USERNAME = input("Enter NetBrain Username: ").strip()
PASSWORD = getpass.getpass("Enter NetBrain Password: ").strip()

site_input = input("Enter Target Site [default: DDC1]: ").strip().upper()
TARGET_SITE = site_input if site_input else "DDC1"

if not USERNAME or not PASSWORD:
    sys.exit("Error: Username and Password cannot be empty.")

BASE_URL = "https://netbrain.mckesson.com/ServicesAPI/API/V1"
OUTPUT_FILE = os.path.expanduser(f"~/Downloads/{TARGET_SITE.lower()}_network_inventory.csv")

MAX_WORKERS = 10
PAGE_LIMIT = 100

session = requests.Session()
session.verify = False

# Optimize HTTP connection pool
adapter = requests.adapters.HTTPAdapter(
    pool_connections=50, 
    pool_maxsize=50, 
    max_retries=2
)
session.mount("https://", adapter)
session.mount("http://", adapter)

DNS_CACHE = {}


def authenticate() -> dict:
    login_url = f"{BASE_URL}/Session"
    login_payload = {"username": USERNAME, "password": PASSWORD}

    try:
        res = session.post(login_url, json=login_payload, timeout=60)
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        sys.exit(f"Auth error: {e}")

    data = res.json()
    token = data.get("token") or data.get("tokenID")
    if not token:
        sys.exit("Error: Token missing in response payload.")

    session.headers.update({
        "Token": token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    })

    if "tenantId" in data and "domainId" in data:
        session.headers.update({
            "tenantId": str(data["tenantId"]),
            "domainId": str(data["domainId"])
        })
    return data


def fetch_all_devices() -> list:
    """Dynamically paginates through NetBrain CMDB devices until no more are returned."""
    all_devices = []
    skip = 0

    while True:
        url = f"{BASE_URL}/CMDB/Devices"
        try:
            res = session.get(url, params={"skip": skip, "limit": PAGE_LIMIT}, timeout=30)
            if res.status_code != 200:
                break
            
            devices = res.json().get("devices", [])
            if not devices:
                break

            all_devices.extend(devices)
            skip += PAGE_LIMIT
            
            if len(devices) < PAGE_LIMIT:
                break
        except requests.RequestException:
            break

    return all_devices


def fetch_device_attributes(hostname: str) -> dict:
    """Queries CMDB Device Attributes passing attributeNames=sn,model."""
    url = f"{BASE_URL}/CMDB/Devices/Attributes"
    params = {
        "hostname": hostname,
        "attributeNames": "sn,serialNumber,model"
    }
    try:
        res = session.get(url, params=params, timeout=15)
        if res.status_code == 200:
            return res.json().get("attributes", {})
    except requests.RequestException:
        pass
    return {}


def fetch_all_interface_attrs(hostname: str) -> dict:
    """Retrieves all interface attributes for a given hostname in a single API call."""
    url = f"{BASE_URL}/CMDB/Interfaces/Attributes"
    try:
        r = session.get(url, params={"hostname": hostname}, timeout=15)
        if r.status_code == 200:
            return r.json().get("attributes", {})
    except requests.RequestException:
        pass
    return {}


def decode_domain_info(device: dict, hostname: str, raw_domain: str) -> str:
    """Derives DNS domain name from attributes or hostname structure."""
    if raw_domain and raw_domain.upper() != "N/A":
        clean = raw_domain.strip().lower()
        if "." in clean:
            return clean

    if hostname and "." in hostname:
        parts = hostname.split(".", 1)
        if len(parts) > 1 and parts[1]:
            return parts[1].strip().lower()

    fqdn = device.get("fqdn") or device.get("hostFQDN") or ""
    if fqdn and "." in fqdn:
        parts = fqdn.split(".", 1)
        if len(parts) > 1 and parts[1]:
            return parts[1].strip().lower()

    if TARGET_SITE in hostname.upper():
        return f"{TARGET_SITE.lower()}.internal.local"

    return "N/A"


def extract_interface_type(intf_name: str) -> str:
    """Extracts base interface prefix type (e.g., vlan, Eth)."""
    if not intf_name:
        return ""
    match = re.match(r"^([a-zA-Z-]+)", str(intf_name).strip())
    if match:
        prefix = match.group(1).rstrip("-")
        if len(prefix) >= 2:
            return prefix
    return ""


def extract_site_from_device(device: dict) -> str:
    """Extracts site location metadata from device payload."""
    for key in ["siteName", "site", "sitePath", "location", "site_name"]:
        val = device.get(key)
        if val and isinstance(val, str) and val.strip():
            return val.strip()

    hostname = device.get("name") or device.get("hostName") or device.get("hostname") or ""
    if hostname:
        parts = hostname.split("-")
        if parts:
            return parts[0].strip()

    return TARGET_SITE


def resolve_ptr(ip_str: str, hostname_fallback: str = "") -> str:
    """Performs reverse DNS lookup with in-memory caching."""
    clean_ip = ip_str.split("/")[0].strip()
    if not clean_ip or clean_ip.upper() == "N/A":
        return "N/A"

    if clean_ip in DNS_CACHE:
        return DNS_CACHE[clean_ip]

    try:
        dns_name, _, _ = socket.gethostbyaddr(clean_ip)
        result = f"{clean_ip} ({dns_name})"
    except Exception:
        result = f"{clean_ip} ({hostname_fallback})" if hostname_fallback and hostname_fallback.upper() != "N/A" else clean_ip

    DNS_CACHE[clean_ip] = result
    return result


def enrich_device_metadata(hostname: str, raw_device: dict) -> tuple:
    """Enriches device metadata concurrently using bulk attribute fetching."""
    types, vrfs, ip_addrs, dns_resolved_ips = set(), set(), set(), set()
    nat_interfaces, pat_interfaces, speeds = set(), set(), set()

    if not hostname:
        return ["N/A"], ["default"], ["N/A"], ["N/A"], "No", "No", "N/A", "N/A", "N/A"

    mgmt_ip = raw_device.get("mgmtIP") or raw_device.get("ip") or ""
    if mgmt_ip:
        ip_addrs.add(mgmt_ip)
        dns_resolved_ips.add(resolve_ptr(mgmt_ip, hostname))

    # Fetch device attributes and all interface attributes concurrently
    with ThreadPoolExecutor(max_workers=2) as inner_executor:
        future_attrs = inner_executor.submit(fetch_device_attributes, hostname)
        future_intf_attrs = inner_executor.submit(fetch_all_interface_attrs, hostname)

        dev_attrs = future_attrs.result()
        all_intf_attrs = future_intf_attrs.result()

    # Parse device attribute results
    sn_val = dev_attrs.get("sn") or dev_attrs.get("serialNumber") or "N/A"
    model_val = dev_attrs.get("model") or "N/A"

    # Process bulk interface attributes in memory
    for intf_name, attrs in all_intf_attrs.items():
        if not isinstance(attrs, dict):
            continue

        if_type = extract_interface_type(intf_name)
        if if_type:
            types.add(if_type)

        speed_val = attrs.get("speed") or attrs.get("bandwidth") or attrs.get("interfaceSpeed")
        if speed_val and str(speed_val).strip() and str(speed_val).upper() != "N/A":
            speeds.add(str(speed_val).strip())

        vrf = str(attrs.get("mplsVrf") or attrs.get("vrfName") or attrs.get("vrf") or "").strip()
        nat_val = attrs.get("isNatIntf") or attrs.get("natType") or attrs.get("nat")
        pat_val = attrs.get("isPatIntf") or attrs.get("patType") or attrs.get("pat")

        if vrf and vrf.lower() not in ["none", "null", "undefined", "n/a", "0"]:
            vrfs.add(vrf)

        ips_raw = attrs.get("ips") or attrs.get("ipAddress")
        if isinstance(ips_raw, list):
            for item in ips_raw:
                ip_str = item.get("ipLoc") if isinstance(item, dict) else item
                if isinstance(ip_str, str) and ip_str.strip():
                    ip_addrs.add(ip_str.strip())
                    dns_resolved_ips.add(resolve_ptr(ip_str.strip(), hostname))
        elif isinstance(ips_raw, str) and ips_raw.strip():
            ip_addrs.add(ips_raw.strip())
            dns_resolved_ips.add(resolve_ptr(ips_raw.strip(), hostname))

        if nat_val and str(nat_val).lower() not in ["false", "0", "disabled", "no", ""]:
            nat_interfaces.add(intf_name)
        if pat_val and str(pat_val).lower() not in ["false", "0", "disabled", "no", ""]:
            pat_interfaces.add(intf_name)

    valid_vrfs = sorted(list(vrfs)) if vrfs else ["default"]
    nat_summary = "\n".join(sorted(nat_interfaces)) if nat_interfaces else "No"
    pat_summary = "\n".join(sorted(pat_interfaces)) if pat_interfaces else "No"
    valid_dns_ips = [ip for ip in dns_resolved_ips if ip and ip != "N/A"]
    speed_summary = "\n".join(sorted(speeds)) if speeds else "N/A"

    return (
        list(types),
        valid_vrfs,
        list(ip_addrs),
        valid_dns_ips if valid_dns_ips else ["N/A"],
        nat_summary,
        pat_summary,
        sn_val,
        model_val,
        speed_summary,
    )


def main():
    authenticate()

    site_devices = []
    seen_hostnames = set()
    all_discovered_columns = {
        "requestedSite",
        "serialNumber",
        "hardwareModel",
        "interfaceTypes",
        "interfaceSpeed",
        "vrfNames",
        "interfaceIPs",
        "dnsResolvedIPs",
        "decodedDomain",
        "hasNAT",
        "hasPAT",
    }
    
    EXCLUDED_FIELDS = {
        "hostName",
        "hostname",
        "mgmtIP",
        "domain",
        "domainName",
        "dnsDomain",
    }

    print(f"Fetching global CMDB devices for target site '{TARGET_SITE}'...")
    raw_devices = fetch_all_devices()

    for device in raw_devices:
        hostname = (
            device.get("hostName")
            or device.get("hostname")
            or device.get("name")
        )

        if hostname and hostname not in seen_hostnames:
            searchable_fields = f"{hostname} {device.get('mgmtIP', '')} {device.get('subType', '')}".upper()

            if TARGET_SITE in searchable_fields:
                seen_hostnames.add(hostname)
                flat_device = {"_raw_device": device}
                flat_device["requestedSite"] = extract_site_from_device(device)

                raw_domain = (
                    device.get("domain")
                    or device.get("domainName")
                    or device.get("dnsDomain")
                    or "N/A"
                )
                flat_device["decodedDomain"] = decode_domain_info(device, hostname, raw_domain)

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
                site_devices.append(flat_device)

    print(f"Found {len(site_devices)} assets matching '{TARGET_SITE}'. Enriching metadata ({MAX_WORKERS} workers)...")

    if site_devices:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_map = {
                executor.submit(
                    enrich_device_metadata,
                    dev.get("name") or dev.get("hostName") or dev.get("hostname"),
                    dev.get("_raw_device", {}),
                ): dev
                for dev in site_devices
            }

            for future in as_completed(future_map):
                dev = future_map[future]
                try:
                    types, vrfs, ips, dns_ips, nat_res, pat_res, sn_res, model_res, speed_res = future.result()
                    dev["interfaceTypes"] = "\n".join(sorted(types)) if types else "N/A"
                    dev["interfaceSpeed"] = speed_res
                    dev["vrfNames"] = "\n".join(vrfs)
                    dev["interfaceIPs"] = "\n".join(sorted(ips)) if ips else "N/A"
                    dev["dnsResolvedIPs"] = "\n".join(sorted(dns_ips)) if dns_ips else "N/A"
                    dev["hasNAT"] = nat_res
                    dev["hasPAT"] = pat_res
                    dev["serialNumber"] = sn_res
                    dev["hardwareModel"] = model_res
                except Exception:
                    dev["interfaceTypes"] = "N/A"
                    dev["interfaceSpeed"] = "N/A"
                    dev["vrfNames"] = "default"
                    dev["interfaceIPs"] = "N/A"
                    dev["dnsResolvedIPs"] = "N/A"
                    dev["hasNAT"] = "No"
                    dev["hasPAT"] = "No"
                    dev["serialNumber"] = "N/A"
                    dev["hardwareModel"] = "N/A"
                finally:
                    dev.pop("_raw_device", None)

    # Primary header ordering
    primary_headers = [
        "name",
        "requestedSite",
        "serialNumber",
        "hardwareModel",
        "decodedDomain",
        "interfaceIPs",
        "dnsResolvedIPs",
        "interfaceTypes",
        "interfaceSpeed",
        "vrfNames",
        "hasNAT",
        "hasPAT",
    ]
    extra_headers = sorted(
        [
            col
            for col in all_discovered_columns
            if col not in primary_headers and col not in EXCLUDED_FIELDS
        ]
    )
    ordered_headers = primary_headers + extra_headers

    output_dir = os.path.dirname(OUTPUT_FILE)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file, fieldnames=ordered_headers, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(site_devices)

    print(f"Export successful: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()