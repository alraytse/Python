#!/usr/bin/env python3

import csv
import paramiko
import getpass
import logging
import sys
from datetime import datetime

CSV_FILE = (
    f"low_counter_interfaces_"
    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
)

LOG_FILE = (
    f"interface_check_"
    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)


def run_command(ssh, command):

    logging.info(f"Executing command: {command}")

    stdin, stdout, stderr = ssh.exec_command(command)

    output = stdout.read().decode(
        "utf-8",
        errors="ignore"
    )

    error = stderr.read().decode(
        "utf-8",
        errors="ignore"
    )

    if error:
        logging.warning(error)

    return output


def get_interface_descriptions(ssh):

    descriptions = {}

    try:

        output = run_command(
            ssh,
            "show interface description"
        )

        for line in output.splitlines():

            line = line.strip()

            if (
                not line
                or line.startswith("Interface")
                or line.startswith("Port")
                or line.startswith("---")
            ):
                continue

            parts = line.split()

            if len(parts) < 4:
                continue

            interface = parts[0]

            description = " ".join(parts[3:])

            descriptions[interface] = description

    except Exception as e:

        logging.warning(
            f"Unable to collect descriptions: {e}"
        )

    return descriptions


def get_interface_details(ssh):

    details = {}

    try:

        output = run_command(
            ssh,
            "show interface status"
        )

        for line in output.splitlines():

            line = line.strip()

            if (
                not line
                or line.startswith("Port")
                or line.startswith("---")
            ):
                continue

            parts = line.split()

            if len(parts) < 6:
                continue

            interface = parts[0]
            vlan = parts[-3]
            speed = parts[-1]

            details[interface] = {
                "vlan": vlan,
                "speed": speed
            }

    except Exception as e:

        logging.warning(
            f"Unable to collect VLAN/speed information: {e}"
        )

    return details


def find_low_counter_interfaces(
        counter_output,
        descriptions,
        interface_details,
        threshold):

    interfaces = []

    for line in counter_output.splitlines():

        line = line.strip()

        if (
            not line
            or line.startswith("Port")
            or line.startswith("Interface")
            or line.startswith("---")
        ):
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        interface = parts[0]

        counters = []

        for value in parts[1:]:

            value = value.replace(",", "")

            try:
                counters.append(int(value))
            except ValueError:
                pass

        if not counters:
            continue

        if all(counter < threshold for counter in counters):

            interfaces.append({
                "interface": interface,
                "description": descriptions.get(
                    interface,
                    "No Description"
                ),
                "vlan": interface_details.get(
                    interface,
                    {}
                ).get(
                    "vlan",
                    "Unknown"
                ),
                "speed": interface_details.get(
                    interface,
                    {}
                ).get(
                    "speed",
                    "Unknown"
                ),
                "counters": counters
            })

    return interfaces


def connect_and_check(
        host,
        username,
        password,
        threshold):

    logging.info(f"Connecting to {host}")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    try:

        ssh.connect(
            hostname=host,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=15
        )

        descriptions = get_interface_descriptions(ssh)

        interface_details = get_interface_details(ssh)

        counter_output = run_command(
            ssh,
            "show interface counters"
        )

        ssh.close()

        return find_low_counter_interfaces(
            counter_output,
            descriptions,
            interface_details,
            threshold
        )

    except Exception as e:

        logging.error(f"{host}: {e}")

        return f"ERROR: {e}"


def main():

    hosts_input = input(
        "\nEnter switch hostnames/IPs (comma separated): "
    ).strip()

    username = input("Username: ")

    password = getpass.getpass("Password: ")

    threshold_input = input(
        "Counter Threshold "
    ).strip()

    threshold = (
        int(threshold_input)
        if threshold_input
        else 200
    )

    hosts = [
        host.strip()
        for host in hosts_input.split(",")
        if host.strip()
    ]

    with open(
        CSV_FILE,
        "w",
        newline=""
    ) as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            "Device",
            "Interface",
            "VLAN",
            "Speed",
            "Description",
            "Notes",
            "Circuit Directly Attached",
            "Circuit Vendor",
            "Cable Trace",
            "Interface Counters"
        ])

        for host in hosts:

            print(f"\nProcessing {host}...")

            result = connect_and_check(
                host,
                username,
                password,
                threshold
            )

            if isinstance(result, str):
                continue

            for item in result:

                counter_string = ",".join(
                    map(str, item["counters"])
                )

                writer.writerow([
                    host,
                    item["interface"],
                    item["vlan"],
                    item["speed"],
                    item["description"],
                    "",
                    "",
                    "",
                    "",
                    counter_string
                ])

                logging.info(
                    f"{host},"
                    f"{item['interface']},"
                    f"{item['vlan']},"
                    f"{item['speed']},"
                    f"{item['description']},"
                    f"{counter_string}"
                )

    print("\nCompleted.")
    print(f"CSV Report : {CSV_FILE}")
    print(f"Log File   : {LOG_FILE}")


if __name__ == "__main__":
    main()