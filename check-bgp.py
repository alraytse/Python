#!/usr/bin/env python3

import csv
import getpass
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import pandas as pd
from netmiko import ConnectHandler

INPUT_CSV = "bgp_neighbors.csv"
OUTPUT_MOP = "BGP_Idle_Neighbor_Shutdown_MOP.txt"

def parse_valid_asn(value):
    """
    Return a valid ASN string for decimal or Cisco asdot notation.

    Valid range:
        1–4,294,967,295
    """

    value = str(value).strip()

    if not value or value.upper() in {
        "NAN",
        "UNKNOWN",
        "NOT_FOUND",
    }:
        return None

    match = re.fullmatch(
        r"(?:router\s+bgp\s+)?(\d+(?:\.\d+)?)",
        value,
        re.IGNORECASE,
    )

    if not match:
        return None

    asn = match.group(1)

    if re.fullmatch(r"\d+", asn):
        numeric_asn = int(asn)

        if 1 <= numeric_asn <= 4_294_967_295:
            return asn

        return None

    asdot_match = re.fullmatch(r"(\d+)\.(\d+)", asn)

    if not asdot_match:
        return None

    high = int(asdot_match.group(1))
    low = int(asdot_match.group(2))

    if high > 65_535 or low > 65_535:
        return None

    numeric_asn = (high * 65_536) + low

    if 1 <= numeric_asn <= 4_294_967_295:
        return asn

    return None

def get_router_bgp(row):
    """
    Determine a safe router BGP statement using a validated ASN.

    Invalid or untrusted values are not written into the MOP.
    """

    router_bgp = str(row.get("router_bgp", "")).strip()
    local_asn = str(row.get("local_asn", "")).strip()

    router_asn = parse_valid_asn(router_bgp)

    if router_asn:
        return f"router bgp {router_asn}"

    local_asn = parse_valid_asn(local_asn)

    if local_asn:
        return f"router bgp {local_asn}"

    return None

def main():
    print("\nReading BGP CSV...")

    try:
        df = pd.read_csv(INPUT_CSV)

    except Exception as exc:
        print(f"Error reading CSV: {exc}")
        return

    required_columns = [
        "device",
        "neighbor",
        "state",
    ]

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:
        print(f"Missing columns: {missing}")
        return

    idle_df = df[
        df["state"]
        .astype(str)
        .str.strip()
        .str.lower()
        .eq("idle")
    ]

    if idle_df.empty:
        print("No Idle neighbors found.")
        return

    with open(
        OUTPUT_MOP,
        "w",
        encoding="utf-8",
    ) as file:
        file.write("=" * 80 + "\n")
        file.write("BGP IDLE NEIGHBOR SHUTDOWN MOP\n")
        file.write("=" * 80 + "\n\n")

        file.write(f"Generated: {datetime.now()}\n\n")

        file.write("PURPOSE\n")
        file.write("-" * 80 + "\n")
        file.write(
            "Administratively shut down BGP neighbors currently "
            "reporting an Idle state.\n\n"
        )

        file.write("CHANGE RISK\n")
        file.write("-" * 80 + "\n")
        file.write(
            "Low to Moderate. Validate all neighbors before shutdown.\n\n"
        )

        file.write("PRE-CHANGE VALIDATION\n")
        file.write("-" * 80 + "\n")
        file.write("show clock\n")
        file.write("show bgp summary\n")
        file.write("show ip bgp summary\n")
        file.write("show bgp vrf all summary\n")
        file.write("show run | sec router bgp\n")
        file.write("show logging last 100\n\n")

        file.write("IDLE NEIGHBORS IDENTIFIED\n")
        file.write("-" * 80 + "\n")

        for _, row in idle_df.iterrows():
            device = row["device"]
            neighbor = row["neighbor"]
            remote_as = row.get("remote_as", "")

            file.write(
                f"{device:<25} "
                f"{neighbor:<20} "
                f"Remote-AS {remote_as}\n"
            )

        file.write("\n")
        file.write("=" * 80 + "\n")
        file.write("IMPLEMENTATION STEPS\n")
        file.write("=" * 80 + "\n\n")

        for device in sorted(idle_df["device"].unique()):
            file.write(f"\nDEVICE: {device}\n")
            file.write("-" * 80 + "\n\n")

            device_df = idle_df[
                idle_df["device"] == device
            ]

            first_row = device_df.iloc[0]
            bgp_stmt = get_router_bgp(first_row)

            file.write("configure terminal\n")

            if not bgp_stmt:
                file.write(
                    "! WARNING - VALID ASN NOT DISCOVERED\n"
                    "! ASN MUST BE VERIFIED MANUALLY\n"
                    "! NO NEIGHBOR SHUTDOWN COMMANDS GENERATED\n\n"
                )
                continue

            file.write(f"{bgp_stmt}\n")

            for _, row in device_df.iterrows():
                neighbor = str(row["neighbor"]).strip()

                if not neighbor:
                    file.write(
                        "! WARNING - EMPTY NEIGHBOR VALUE SKIPPED\n"
                    )
                    continue

                if not re.fullmatch(
                    r"\d+\.\d+\.\d+\.\d+",
                    neighbor,
                ):
                    file.write(
                        f"! WARNING - INVALID NEIGHBOR VALUE SKIPPED: "
                        f"{neighbor}\n"
                    )
                    continue

                file.write(
                    f" neighbor {neighbor} shutdown\n"
                )

            file.write(
                " exit\n"
                "end\n"
                "copy running-config startup-config\n\n"
            )

        file.write("=" * 80 + "\n")
        file.write("POST-CHANGE VALIDATION\n")
        file.write("=" * 80 + "\n\n")

        file.write("show bgp summary\n")
        file.write("show ip bgp summary\n")
        file.write("show bgp vrf all summary\n")
        file.write("show run | sec router bgp\n")
        file.write("show logging last 100\n\n")

        file.write("=" * 80 + "\n")
        file.write("ROLLBACK PROCEDURE\n")
        file.write("=" * 80 + "\n\n")

        for device in sorted(idle_df["device"].unique()):
            file.write(f"\nDEVICE: {device}\n")
            file.write("-" * 80 + "\n\n")

            device_df = idle_df[
                idle_df["device"] == device
            ]

            first_row = device_df.iloc[0]
            bgp_stmt = get_router_bgp(first_row)

            file.write("configure terminal\n")

            if not bgp_stmt:
                file.write(
                    "! WARNING - VALID ASN NOT DISCOVERED\n"
                    "! MANUAL ROLLBACK REQUIRED\n\n"
                )
                continue

            file.write(f"{bgp_stmt}\n")

            for _, row in device_df.iterrows():
                neighbor = str(row["neighbor"]).strip()

                if not re.fullmatch(
                    r"\d+\.\d+\.\d+\.\d+",
                    neighbor,
                ):
                    file.write(
                        f"! WARNING - INVALID NEIGHBOR VALUE SKIPPED: "
                        f"{neighbor}\n"
                    )
                    continue

                file.write(
                    f" no neighbor {neighbor} shutdown\n"
                )

            file.write(
                " exit\n"
                "end\n"
                "copy running-config startup-config\n\n"
            )

        file.write("=" * 80 + "\n")
        file.write("POST-ROLLBACK VALIDATION\n")
        file.write("=" * 80 + "\n\n")

        file.write("show bgp summary\n")
        file.write("show ip bgp summary\n")
        file.write("show bgp vrf all summary\n")
        file.write("show run | sec router bgp\n")
        file.write("show logging last 100\n")

    print("\nMOP created successfully")
    print(f"Output file: {OUTPUT_MOP}")
    print(f"Idle neighbors found: {len(idle_df)}")

if __name__ == "__main__":
    main()
