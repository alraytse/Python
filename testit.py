#!/usr/bin/env python3

import requests
import urllib3
import getpass
import csv
import json
import ipaddress
from datetime import datetime

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

DEVICES_CSV = f"netbrain_devices_{TIMESTAMP}.csv"
RAW_JSON_FILE = f"netbrain_devices_raw_{TIMESTAMP}.json"

session = requests.Session()
session.verify = False


def login(server, username, password):

    url = (
        f"https://{server}"
        "/ServicesAPI/API/V1/Session"
    )

    payload = {
        "username": username,
        "password": password,
        "authentication_id": ""
    }

    response = session.post(
        url,
        json=payload,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    if data.get("statusCode") != 790200:

        raise Exception(
            f"Login Failed: {data}"
        )

    token = data["token"]

    session.headers.update({
        "Token": token
    })

    return token


def get_devices(server):

    url = (
        f"https://{server}"
        "/ServicesAPI/API/V1/CMDB/Devices"
    )

    response = session.get(
        url,
        timeout=60
    )

    print(
        f"\nHTTP Status: {response.status_code}"
    )

    response.raise_for_status()

    data = response.json()

    with open(
        RAW_JSON_FILE,
        "w",
        encoding="utf-8"
    ) as fh:

        json.dump(
            data,
            fh,
            indent=4
        )

    print(
        f"\nRaw JSON saved to: {RAW_JSON_FILE}"
    )

    return data


def extract_devices(data):

    if isinstance(data, list):
        return data

    if not isinstance(data, dict):
        return []

    for key in [
        "devices",
        "Devices",
        "deviceList",
        "data",
    ]:

        if key in data:
            return data[key]

    return []


def find_by_name(
    devices,
    search_text
):

    search_text = search_text.lower()

    matches = []

    for device in devices:

        name = str(
            device.get(
                "name",
                ""
            )
        ).lower()

        if search_text in name:
            matches.append(device)

    return matches


def find_by_ip(
    devices,
    search_ip
):

    matches = []

    for device in devices:

        mgmt_ip = device.get(
            "mgmtIP",
            ""
        )

        if mgmt_ip == search_ip:

            matches.append(device)

    return matches


def find_devices_in_subnet(
    devices,
    subnet
):

    network = ipaddress.ip_network(
        subnet,
        strict=False
    )

    matches = []

    checked = 0

    for device in devices:

        mgmt_ip = device.get(
            "mgmtIP",
            ""
        )

        if not mgmt_ip:
            continue

        checked += 1

        try:

            ip_obj = ipaddress.ip_address(
                mgmt_ip
            )

            if ip_obj in network:

                matches.append(device)

        except Exception:
            pass

    print(
        f"\nDevices Checked : {checked}"
    )

    print(
        f"Devices Matched : {len(matches)}"
    )

    return matches


def export_devices_csv(
    results,
    filename
):

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as fh:

        writer = csv.writer(fh)

        if (
            results and
            isinstance(results, list) and
            isinstance(results[0], dict)
        ):

            headers = sorted(
                results[0].keys()
            )

            writer.writerow(headers)

            for row in results:

                writer.writerow([
                    row.get(header, "")
                    for header in headers
                ])

        else:

            writer.writerow(
                ["No Results"]
            )

    print(
        f"\nCSV Exported: {filename}"
    )


def test_endpoint(server):

    endpoint = input(
        "\nEndpoint: "
    ).strip()

    parameter = input(
        "Parameter Name: "
    ).strip()

    value = input(
        "Parameter Value: "
    ).strip()

    url = (
        f"https://{server}"
        f"{endpoint}"
    )

    response = session.get(
        url,
        params={
            parameter: value
        },
        timeout=30
    )

    print("\nURL:")
    print(response.url)

    print("\nHTTP Status:")
    print(response.status_code)

    print("\nResponse:")
    print(response.text[:5000])


def display_sample_devices(devices):

    print("\nSample Devices")
    print("-" * 80)

    for device in devices[:10]:

        print(
            f"{device.get('name','N/A'):40} "
            f"{device.get('mgmtIP','N/A')}"
        )


def main():

    print("=" * 60)
    print("NetBrain R12 Search Tool")
    print("=" * 60)

    server = input(
        "\nNetBrain IP Address: "
    ).strip()

    username = input(
        "Username: "
    ).strip()

    password = getpass.getpass(
        "Password: "
    )

    try:

        print("\nLogging in...")

        token = login(
            server,
            username,
            password
        )

        print("\nLogin Successful")
        print(f"Token: {token}")

        while True:

            print("\n")
            print("1 - List Devices")
            print("2 - Search by Device Name")
            print("3 - Search by IP Address")
            print("4 - Search by Subnet")
            print("5 - Test Endpoint")
            print("6 - Exit")

            choice = input(
                "\nSelection: "
            ).strip()

            if choice == "1":

                data = get_devices(server)

                devices = extract_devices(
                    data
                )

                print(
                    f"\nDevices Returned: {len(devices)}"
                )

                display_sample_devices(
                    devices
                )

                export = input(
                    "\nExport all devices to CSV? (y/n): "
                ).strip().lower()

                if export == "y":

                    export_devices_csv(
                        devices,
                        DEVICES_CSV
                    )

            elif choice == "2":

                search = input(
                    "Device Name: "
                ).strip()

                devices = extract_devices(
                    get_devices(server)
                )

                matches = find_by_name(
                    devices,
                    search
                )

                print(
                    json.dumps(
                        matches,
                        indent=4
                    )[:10000]
                )

            elif choice == "3":

                search_ip = input(
                    "IP Address: "
                ).strip()

                devices = extract_devices(
                    get_devices(server)
                )

                matches = find_by_ip(
                    devices,
                    search_ip
                )

                print(
                    json.dumps(
                        matches,
                        indent=4
                    )[:10000]
                )

            elif choice == "4":

                subnet = input(
                    "Subnet (example 10.254.192.0/24): "
                ).strip()

                devices = extract_devices(
                    get_devices(server)
                )

                matches = find_devices_in_subnet(
                    devices,
                    subnet
                )

                print(
                    json.dumps(
                        matches,
                        indent=4
                    )[:10000]
                )

                export = input(
                    "\nExport results to CSV? (y/n): "
                ).strip().lower()

                if export == "y":

                    filename = (
                        f"netbrain_subnet_search_{TIMESTAMP}.csv"
                    )

                    export_devices_csv(
                        matches,
                        filename
                    )

            elif choice == "5":

                test_endpoint(
                    server
                )

            elif choice == "6":

                break

            else:

                print(
                    "Invalid selection"
                )

    except Exception as exc:

        print(
            f"\nERROR: {exc}"
        )


if __name__ == "__main__":
    main()