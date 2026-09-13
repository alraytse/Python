import csv
import getpass
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

# ---------------------------------------------------------------------------
# Interactive Inputs
# ---------------------------------------------------------------------------
USERNAME = input("Enter NetBrain Username: ").strip()
PASSWORD = getpass.getpass("Enter NetBrain Password: ").strip()

site_input = input("Enter Target Site [default: DDC1]: ").strip().upper()
TARGET_SITE = site_input if site_input else "DDC1"

if not USERNAME or not PASSWORD:
    sys.exit("Error: Username and Password cannot be empty.")

BASE_URL = "https://netbrain.mckesson.com/ServicesAPI/API/V1"
OUTPUT_FILE = os.path.expanduser(f"~/Downloads/{TARGET_SITE.lower()}_network_inventory.csv")

MAX_WORKERS = 30
PAGE_LIMIT = 100
MAX_ESTIMATED_PAGES = 100

session = requests.Session()
session.verify = False
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def authenticate() -> dict:
    """Authenticates with NetBrain and populates session tokens and headers."""
    login_url = f"{BASE_URL}/Session"
    login_payload = {"username": USERNAME, "password": PASSWORD}

    try:
        res = session.post(login_url, json=login_payload, timeout=60)
        res.raise_for_status()
    except requests.exceptions.Timeout:
        sys.exit("Error: Authentication request timed out (60s). Check network/VPN.")
    except requests.exceptions.RequestException as e:
        sys.exit(f"Auth network error: {e}")

    data = res.json()
    token = data.get("token")
    if not token:
        sys.exit("Error: Token missing in response payload.")

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
    """Fetches a paginated slice of device inventory from NetBrain CMDB."""
    url = f"{BASE_URL}/CMDB/Devices"
    try:
        res = session.get(
            url, params={"skip": skip_value, "limit": PAGE_LIMIT}, timeout=30
        )
        return res.json().get("devices", []) if res.status_code == 200 else []
    except requests.RequestException:
        return []


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
    """Performs reverse DNS lookup for interface IP addresses."""
    clean_ip = ip_str.split("/")[0].strip()
    if not clean_ip or clean_ip.upper() == "N/A":
        return "N/A"

    try:
        dns_name, _, _ = socket.gethostbyaddr(clean_ip)
        if dns_name:
            return f"{clean_ip} ({dns_name})"
    except (socket.herror, socket.gaierror, Exception):
        pass

    if hostname_fallback and hostname_fallback.upper() != "N/A":
        return f"{clean_ip} ({hostname_fallback})"

    return clean_ip


def fetch_single_interface_attr(hostname: str, intf_name: str) -> tuple:
    """Retrieves interface VRF, assigned IPs, and NAT/PAT flags."""
    url = f"{BASE_URL}/CMDB/Interfaces/Attributes"
    try:
        r = session.get(url, params={"hostname": hostname, "interfaceName": intf_name}, timeout=10)
        if r.status_code == 200:
            raw_attrs = r.json().get("attributes", {})
            attrs = raw_attrs.get(intf_name, raw_attrs) if isinstance(raw_attrs, dict) else {}

            vrf = str(attrs.get("mplsVrf") or attrs.get("vrfName") or attrs.get("vrf") or "").strip()
            nat_val = attrs.get("isNatIntf") or attrs.get("natType") or attrs.get("nat")
            pat_val = attrs.get("isPatIntf") or attrs.get("patType") or attrs.get("pat")

            found_ips = []
            ips_raw = attrs.get("ips") or attrs.get("ipAddress")
            if isinstance(ips_raw, list):
                for item in ips_raw:
                    if isinstance(item, dict) and item.get("ipLoc"):
                        found_ips.append(item["ipLoc"])
                    elif isinstance(item, str) and item.strip():
                        found_ips.append(item.strip())
            elif isinstance(ips_raw, str) and ips_raw.strip():
                found_ips.append(ips_raw.strip())

            has_nat = bool(nat_val and str(nat_val).lower() not in ["false", "0", "disabled", "no", ""])
            has_pat = bool(pat_val and str(pat_val).lower() not in ["false", "0", "disabled", "no", ""])

            return vrf, found_ips, has_nat, has_pat
    except requests.RequestException:
        pass
    return "", [], False, False


def fetch_ntp_config(hostname: str, raw_device: dict) -> tuple:
    """Multi-vendor parser for configured NTP servers, Stratum, and Reference ID."""
    ntp_servers = set()
    ntp_stratum = "N/A"
    ntp_ref = "N/A"

    attrs = raw_device.get("attributes", {}) if isinstance(raw_device.get("attributes"), dict) else {}

    val = raw_device.get("ntpServers") or attrs.get("ntpServers")
    if val:
        if isinstance(val, list):
            ntp_servers.update(str(item).strip() for item in val if str(item).strip())
        elif isinstance(val, str) and val.strip():
            ntp_servers.add(val.strip())

    config_text = ""
    url = f"{BASE_URL}/CMDB/Devices/RawConfig"
    try:
        r = session.get(url, params={"hostname": hostname}, timeout=12)
        if r.status_code == 200:
            config_text = r.json().get("configText") or r.json().get("rawConfig") or ""
    except requests.RequestException:
        pass

    if config_text:
        cisco_matches = re.findall(r"^\s*ntp\s+(?:peer|server)\s+(?:vrf\s+\S+\s+)?([a-zA-Z0-9\.\-_]+)", config_text, re.M | re.I)
        ntp_servers.update(cisco_matches)

        palo_matches = re.findall(r"ntp-server-(?:1|2)\s+\{\s*primary\s+([a-zA-Z0-9\.\-_]+);", config_text, re.I)
        ntp_servers.update(palo_matches)

        junos_matches = re.findall(r"ntp\s+\{\s*servers\s+\[\s*([0-9\.\s]+)\s*\]", config_text, re.I)
        for jm in junos_matches:
            ntp_servers.update(jm.split())

        stratum_match = re.search(r"(?:stratum|level)\s+(\d+)", config_text, re.I)
        if stratum_match:
            ntp_stratum = stratum_match.group(1)

        ref_match = re.search(r"(?:reference|refid)\s+(?:is\s+)?([a-zA-Z0-9\.\-_]+)", config_text, re.I)
        if ref_match:
            ntp_ref = ref_match.group(1)

    if ntp_stratum == "N/A" or ntp_ref == "N/A":
        cli_url = f"{BASE_URL}/CMDB/Devices/CLI"
        try:
            r = session.post(cli_url, json={"hostname": hostname, "command": "show ntp status"}, timeout=10)
            if r.status_code == 200:
                cli_output = r.json().get("output", "")
                st_match = re.search(r"stratum\s+(\d+)", cli_output, re.I)
                if st_match:
                    ntp_stratum = st_match.group(1)
                rf_match = re.search(r"reference\s+is\s+([a-zA-Z0-9\.\-_]+)", cli_output, re.I)
                if rf_match:
                    ntp_ref = rf_match.group(1)
        except requests.RequestException:
            pass

    summary_str = "\n".join(sorted(list(ntp_servers))) if ntp_servers else "N/A"
    return summary_str, ntp_stratum, ntp_ref


def fetch_dns_config(hostname: str, raw_device: dict) -> str:
    """Multi-vendor parser for configured DNS servers."""
    dns_servers = set()
    dns_keys = ["dnsServers", "dnsServer", "dns_servers", "dns", "nameServer", "nameServers"]
    
    attrs = raw_device.get("attributes", {}) if isinstance(raw_device.get("attributes"), dict) else {}
    for key in dns_keys:
        val = raw_device.get(key) or attrs.get(key)
        if val:
            if isinstance(val, list):
                dns_servers.update(str(item).strip() for item in val if str(item).strip())
            elif isinstance(val, str) and val.strip():
                dns_servers.add(val.strip())

    config_text = ""
    url = f"{BASE_URL}/CMDB/Devices/RawConfig"
    try:
        r = session.get(url, params={"hostname": hostname}, timeout=12)
        if r.status_code == 200:
            config_text = r.json().get("configText") or r.json().get("rawConfig") or ""
    except requests.RequestException:
        pass

    if config_text:
        cisco_dns = re.findall(r"^\s*(?:ip\s+)?name-server\s+(.+)$", config_text, re.M | re.I)
        for match in cisco_dns:
            for item in match.split():
                clean_item = item.strip()
                if clean_item and clean_item.lower() not in ["vrf", "use-vrf", "default"]:
                    dns_servers.add(clean_item)

        palo_dns = re.findall(r"dns-setting\s+\{\s*servers\s+\{\s*primary\s+([0-9\.]+);(?:\s*secondary\s+([0-9\.]+);)?", config_text, re.I)
        for p_match in palo_dns:
            for ip in p_match:
                if ip:
                    dns_servers.add(ip)

    return "\n".join(sorted(list(dns_servers))) if dns_servers else "N/A"


def enrich_device_metadata(hostname: str, raw_device: dict) -> tuple:
    """Enriches device metadata concurrently."""
    types, vrfs, ip_addrs, dns_resolved_ips = set(), set(), set(), set()
    nat_interfaces, pat_interfaces = set(), set()

    if not hostname:
        return ["N/A"], ["default"], ["N/A"], ["N/A"], "No", "No", "N/A", "N/A", "N/A", "N/A"

    ntp_summary, ntp_stratum, ntp_ref = fetch_ntp_config(hostname, raw_device)
    dns_summary = fetch_dns_config(hostname, raw_device)
    mgmt_ip = raw_device.get("mgmtIP") or raw_device.get("ip") or ""

    if mgmt_ip:
        ip_addrs.add(mgmt_ip)
        dns_resolved_ips.add(resolve_ptr(mgmt_ip, hostname))

    url = f"{BASE_URL}/CMDB/Interfaces"
    try:
        r = session.get(url, params={"hostname": hostname}, timeout=15)
        if r.status_code == 200:
            intf_names = r.json().get("interfaces", [])

            for intf in intf_names:
                if_type = extract_interface_type(intf)
                if if_type:
                    types.add(if_type)

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(fetch_single_interface_attr, hostname, intf): intf
                    for intf in intf_names
                }
                for future in as_completed(futures):
                    intf_name = futures[future]
                    vrf, ips, has_nat, has_pat = future.result()

                    if vrf and vrf.lower() not in ["none", "null", "undefined", "n/a", "0"]:
                        vrfs.add(vrf)
                    for ip in ips:
                        ip_addrs.add(ip)
                        dns_resolved_ips.add(resolve_ptr(ip, hostname))
                    if has_nat:
                        nat_interfaces.add(intf_name)
                    if has_pat:
                        pat_interfaces.add(intf_name)

    except requests.RequestException:
        pass

    valid_vrfs = sorted(list(vrfs)) if vrfs else ["default"]
    nat_summary = "\n".join(sorted(nat_interfaces)) if nat_interfaces else "No"
    pat_summary = "\n".join(sorted(pat_interfaces)) if pat_interfaces else "No"
    valid_dns_ips = [ip for ip in dns_resolved_ips if ip and ip != "N/A"]

    return (
        list(types),
        valid_vrfs,
        list(ip_addrs),
        valid_dns_ips if valid_dns_ips else ["N/A"],
        nat_summary,
        pat_summary,
        ntp_summary,
        ntp_stratum,
        ntp_ref,
        dns_summary,
    )


def main():
    authenticate()

    site_devices = []
    seen_hostnames = set()
    all_discovered_columns = {
        "requestedSite",
        "interfaceTypes",
        "vrfNames",
        "interfaceIPs",
        "dnsResolvedIPs",
        "decodedDomain",
        "ntpServers",
        "ntpStratum",
        "ntpRef",
        "dnsServers",
        "hasNAT",
        "hasPAT",
    }
    skip_offsets = [i * PAGE_LIMIT for i in range(MAX_ESTIMATED_PAGES)]
    EXCLUDED_FIELDS = {
        "hostName",
        "hostname",
        "mgmtIP",
        "domain",
        "domainName",
        "dnsDomain",
    }

    print(f"Fetching global CMDB devices for target site '{TARGET_SITE}' ({MAX_WORKERS} workers)...")

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

    print(f"Found {len(site_devices)} assets matching '{TARGET_SITE}'. Enriching metadata, NTP, DNS & Interfaces...")

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
                    types, vrfs, ips, dns_ips, nat_res, pat_res, ntp_res, stratum_res, ref_res, dns_res = future.result()
                    dev["interfaceTypes"] = "\n".join(sorted(types)) if types else "N/A"
                    dev["vrfNames"] = "\n".join(vrfs)
                    dev["interfaceIPs"] = "\n".join(sorted(ips)) if ips else "N/A"
                    dev["dnsResolvedIPs"] = "\n".join(sorted(dns_ips)) if dns_ips else "N/A"
                    dev["hasNAT"] = nat_res
                    dev["hasPAT"] = pat_res
                    dev["ntpServers"] = ntp_res
                    dev["ntpStratum"] = stratum_res
                    dev["ntpRef"] = ref_res
                    dev["dnsServers"] = dns_res
                except Exception:
                    dev["interfaceTypes"] = "N/A"
                    dev["vrfNames"] = "default"
                    dev["interfaceIPs"] = "N/A"
                    dev["dnsResolvedIPs"] = "N/A"
                    dev["hasNAT"] = "No"
                    dev["hasPAT"] = "No"
                    dev["ntpServers"] = "N/A"
                    dev["ntpStratum"] = "N/A"
                    dev["ntpRef"] = "N/A"
                    dev["dnsServers"] = "N/A"
                finally:
                    dev.pop("_raw_device", None)

    primary_headers = [
        "name",
        "requestedSite",
        "decodedDomain",
        "dnsServers",
        "ntpServers",
        "ntpStratum",
        "ntpRef",
        "interfaceIPs",
        "dnsResolvedIPs",
        "interfaceTypes",
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

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file, fieldnames=ordered_headers, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(site_devices)

    print(f"Export successful: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()