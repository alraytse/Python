#!/usr/bin/env python3
"""
Infoblox IPAM Utility

An interactive CLI client for querying and exporting network and host
records from an Infoblox Grid Manager via WAPI.
"""

import csv
import getpass
import sys
import requests
import urllib3

# Suppress unverified HTTPS request warnings for internal self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# HARDCODED CONFIGURATION
GRIDMASTER = "gridmaster.mckesson.com"
WAPI_VERSION = "v2.12"


class InfobloxClient:
    def __init__(self, gridmaster: str, eid: str, password: str, wapi_version: str = WAPI_VERSION):
        self.base_url = f"https://{gridmaster}/wapi/{wapi_version}"
        self.session = requests.Session()
        self.session.auth = (eid, password)
        self.session.verify = False  # Set to path of CA bundle if TLS validation is required
        self.timeout = 30

    def _request(self, endpoint: str, params: dict = None) -> list:
        url = f"{self.base_url}/{endpoint}"
        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as exc:
            print("\n" + "=" * 60)
            print("API ERROR")
            print("=" * 60)
            print(f"URL: {url}")
            print(f"Status Code: {response.status_code}")
            print(f"Details: {response.text}")
            print("=" * 60)
            raise exc
        except requests.exceptions.RequestException as exc:
            print(f"\nNetwork Error: {exc}")
            raise exc

    def get_networks(self, max_results: int = 10000) -> list:
        params = {
            "_max_results": max_results,
            "_return_fields": "network,network_view,comment"
        }
        networks = self._request("network", params=params)

        try:
            containers = self._request("networkcontainer", params=params)
            networks.extend(containers)
        except requests.exceptions.RequestException:
            pass

        return networks

    def search_ip(self, ip_address: str) -> list:
        params = {
            "ip_address": ip_address,
            "_return_fields": "ip_address,names,network,mac_address,status"
        }
        return self._request("ipv4address", params=params)

    def search_subnet(self, subnet_pattern: str) -> list:
        pattern = subnet_pattern.strip()
        results = []
        
        # Exact CIDR match
        if "/" in pattern:
            params = {
                "network": pattern,
                "_return_fields": "network,network_view,comment"
            }
            results = self._request("network", params=params)
            try:
                containers = self._request("networkcontainer", params=params)
                results.extend(containers)
            except requests.exceptions.RequestException:
                pass
            return results

        # IP-based lookup fallback when no CIDR mask is provided
        ip_params = {
            "ip_address": pattern,
            "_return_fields": "network"
        }
        ip_matches = self._request("ipv4address", params=ip_params)
        
        discovered_cidrs = {ip["network"] for ip in ip_matches if "network" in ip}

        for net_cidr in discovered_cidrs:
            net_data = self._request(
                "network", 
                params={"network": net_cidr, "_return_fields": "network,network_view,comment"}
            )
            results.extend(net_data)

        return results


def print_table(headers: list, rows: list, widths: list):
    header_str = "".join(f"{h:<{w}}" for h, w in zip(headers, widths))
    divider = "-" * sum(widths)
    print("\n" + divider)
    print(header_str)
    print(divider)
    for row in rows:
        print("".join(f"{str(val):<{w}}" for val, w in zip(row, widths)))
    print(divider)


def display_networks(networks: list):
    if not networks:
        print("\nNo matching networks found.")
        return

    headers = ["Subnet / Container", "Network View", "Comment"]
    widths = [28, 25, 57]
    rows = [
        [
            net.get("network", ""),
            net.get("network_view", "default"),
            net.get("comment", "")[:55]
        ]
        for net in networks
    ]
    
    print_table(headers, rows, widths)
    print(f"Total Networks Found: {len(networks)}")


def display_ip_results(results: list):
    if not results:
        print("\nNo matching IP found.")
        return

    headers = ["IP Address", "Hostname(s)", "Network", "MAC Address", "Status"]
    widths = [18, 35, 22, 20, 12]
    rows = [
        [
            ip.get("ip_address", ""),
            ",".join(ip.get("names", []))[:33],
            ip.get("network", ""),
            ip.get("mac_address", ""),
            ip.get("status", "")
        ]
        for ip in results
    ]

    print_table(headers, rows, widths)


def export_networks_csv(networks: list, filename: str = "infoblox_networks.csv"):
    if not networks:
        print("\nNo networks to export.")
        return

    try:
        with open(filename, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Subnet", "Network View", "Comment"])
            for net in networks:
                writer.writerow([
                    net.get("network", ""),
                    net.get("network_view", "default"),
                    net.get("comment", "")
                ])
        print(f"\nSuccessfully exported {len(networks)} network records to {filename}")
    except OSError as exc:
        print(f"\nFailed to write CSV file: {exc}")


def get_user_credentials() -> dict:
    print("\nInfoblox IPAM Tool")
    print("=" * 60)
    print(f"Target Grid Manager: {GRIDMASTER}")
    print(f"Target WAPI Version: {WAPI_VERSION}")
    print("-" * 60)

    eid = input("EID/Username: ").strip()
    password = getpass.getpass("Password: ")

    return {
        "gridmaster": GRIDMASTER,
        "wapi_version": WAPI_VERSION,
        "eid": eid,
        "password": password
    }


def main():
    creds = get_user_credentials()
    client = InfobloxClient(
        gridmaster=creds["gridmaster"],
        eid=creds["eid"],
        password=creds["password"],
        wapi_version=creds["wapi_version"]
    )

    while True:
        print("\nOptions")
        print("-" * 30)
        print("1 - List All Networks")
        print("2 - Search IP Address")
        print("3 - Search Subnet")
        print("4 - Export All Networks to CSV")
        print("5 - Exit")

        choice = input("\nSelect option [1-5]: ").strip()

        try:
            if choice == "1":
                networks = client.get_networks()
                display_networks(networks)

            elif choice == "2":
                ip = input("\nEnter IP Address: ").strip()
                if ip:
                    results = client.search_ip(ip)
                    display_ip_results(results)

            elif choice == "3":
                subnet = input("\nEnter Subnet CIDR (e.g., 143.112.0.0/16 or IP 143.112.0.1): ").strip()
                if subnet:
                    results = client.search_subnet(subnet)
                    display_networks(results)

            elif choice == "4":
                networks = client.get_networks()
                export_networks_csv(networks)

            elif choice == "5":
                print("\nExiting.")
                break

            else:
                print("\nInvalid selection. Please choose options 1 through 5.")

        except requests.exceptions.RequestException:
            print("\nOperation failed due to an API or network error.")


if __name__ == "__main__":
    main()