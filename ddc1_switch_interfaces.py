#!/usr/bin/env python3

import argparse
import csv
import getpass
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGIN_PATH = "/ServicesAPI/API/V1/Session"
DEVICES_PATH = "/ServicesAPI/API/V1/CMDB/Devices"


class NetBrainClient:

    def __init__(self, base_url, insecure=False):

        self.base_url = base_url.rstrip("/")

        self.session = requests.Session()
        self.session.verify = not insecure

        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json"
        })

    def request(self, method, path, **kwargs):

        url = self.base_url + path

        response = self.session.request(
            method=method,
            url=url,
            timeout=60,
            **kwargs
        )

        response.raise_for_status()

        if response.text:
            return response.json()

        return {}

    def login(self, username, password):

        payload = {
            "username": username,
            "password": password
        }

        response = self.request(
            "POST",
            LOGIN_PATH,
            json=payload
        )

        token = response.get("token")

        if not token:
            raise Exception(
                f"No token returned.\n{response}"
            )

        self.session.headers["Token"] = token
        self.session.headers["Authorization"] = f"Bearer {token}"

        print("Successfully authenticated")

    def get_devices(self):

        devices = []

        response = self.request(
            "GET",
            DEVICES_PATH
        )

        devices.extend(
            response.get("devices", [])
        )

        return devices


def is_ddc1_device(device):

    search_values = [
        str(device.get("name", "")),
        str(device.get("hostName", "")),
        str(device.get("hostname", "")),
        str(device.get("siteName", "")),
        str(device.get("site", "")),
        str(device.get("mgmtIP", "")),
    ]

    combined = " ".join(search_values).upper()

    return "DDC1" in combined


def write_csv(devices, filename):

    fields = [
        "Name",
        "ManagementIP",
        "DeviceType",
        "DeviceID"
    ]

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )

        writer.writeheader()

        for device in devices:

            writer.writerow({
                "Name": device.get("name", ""),
                "ManagementIP": device.get("mgmtIP", ""),
                "DeviceType": device.get("subTypeName", ""),
                "DeviceID": device.get("id", "")
            })


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--base-url",
        required=True
    )

    parser.add_argument(
        "--insecure",
        action="store_true"
    )

    parser.add_argument(
        "--csv-file",
        default="ddc1_devices.csv"
    )

    args = parser.parse_args()

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    client = NetBrainClient(
        args.base_url,
        args.insecure
    )

    print("\nLogging into NetBrain...")
    client.login(username, password)

    print("\nRetrieving devices...")
    all_devices = client.get_devices()

    print(
        f"\nTotal devices returned: "
        f"{len(all_devices)}"
    )

    ddc1_devices = [
        d for d in all_devices
        if is_ddc1_device(d)
    ]

    print(
        f"DDC1 devices found: "
        f"{len(ddc1_devices)}"
    )

    print("\n" + "=" * 120)
    print("DDC1 DEVICES")
    print("=" * 120)

    for device in ddc1_devices:

        print(
            f"{device.get('name',''):<50} "
            f"{device.get('mgmtIP',''):<18} "
            f"{device.get('subTypeName','')}"
        )

    write_csv(
        ddc1_devices,
        args.csv_file
    )

    print(
        f"\nCSV report saved to: "
        f"{args.csv_file}"
    )


if __name__ == "__main__":
    main()