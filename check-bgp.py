#!/usr/bin/env python3

import pandas as pd
from datetime import datetime

INPUT_CSV = "bgp_neighbors.csv"
OUTPUT_MOP = "BGP_Idle_Neighbor_Shutdown_MOP.txt"


def get_router_bgp(row):
    """
    Determine router bgp statement.
    """

    router_bgp = str(row.get("router_bgp", "")).strip()
    local_asn = str(row.get("local_asn", "")).strip()

    if (
        router_bgp
        and router_bgp.upper() != "NOT_FOUND"
        and router_bgp.upper() != "NAN"
    ):
        return router_bgp

    if (
        local_asn
        and local_asn.upper() != "UNKNOWN"
        and local_asn.upper() != "NAN"
    ):
        return f"router bgp {local_asn}"

    return None


def main():

    print("\nReading BGP CSV...")

    try:
        df = pd.read_csv(INPUT_CSV)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return

    required_columns = [
        "device",
        "neighbor",
        "state"
    ]

    missing = [
        col
        for col in required_columns
        if col not in df.columns
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

    with open(OUTPUT_MOP, "w") as f:

        f.write("=" * 80 + "\n")
        f.write("BGP IDLE NEIGHBOR SHUTDOWN MOP\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Generated: {datetime.now()}\n\n")

        f.write("PURPOSE\n")
        f.write("-" * 80 + "\n")
        f.write(
            "Administratively shut down BGP neighbors currently "
            "reporting an Idle state.\n\n"
        )

        f.write("CHANGE RISK\n")
        f.write("-" * 80 + "\n")
        f.write(
            "Low to Moderate. Validate all neighbors before shutdown.\n\n"
        )

        f.write("PRE-CHANGE VALIDATION\n")
        f.write("-" * 80 + "\n")
        f.write("show clock\n")
        f.write("show bgp summary\n")
        f.write("show ip bgp summary\n")
        f.write("show bgp vrf all summary\n")
        f.write("show run | sec router bgp\n")
        f.write("show logging last 100\n\n")

        f.write("IDLE NEIGHBORS IDENTIFIED\n")
        f.write("-" * 80 + "\n")

        for _, row in idle_df.iterrows():

            device = row["device"]
            neighbor = row["neighbor"]
            remote_as = row.get("remote_as", "")

            f.write(
                f"{device:<25} "
                f"{neighbor:<20} "
                f"Remote-AS {remote_as}\n"
            )

        f.write("\n")
        f.write("=" * 80 + "\n")
        f.write("IMPLEMENTATION STEPS\n")
        f.write("=" * 80 + "\n\n")

        for device in sorted(idle_df["device"].unique()):

            f.write(f"\nDEVICE: {device}\n")
            f.write("-" * 80 + "\n\n")

            device_df = idle_df[
                idle_df["device"] == device
            ]

            first_row = device_df.iloc[0]

            bgp_stmt = get_router_bgp(first_row)

            f.write("configure terminal\n")

            if not bgp_stmt:

                f.write(
                    "! WARNING - ASN NOT DISCOVERED\n"
                    "! MANUAL VERIFICATION REQUIRED\n\n"
                )

                continue

            f.write(f"{bgp_stmt}\n")

            for _, row in device_df.iterrows():

                f.write(
                    f" neighbor {row['neighbor']} shutdown\n"
                )

            f.write(
                " exit\n"
                "end\n"
                "copy running-config startup-config\n\n"
            )

        f.write("=" * 80 + "\n")
        f.write("POST-CHANGE VALIDATION\n")
        f.write("=" * 80 + "\n\n")

        f.write("show bgp summary\n")
        f.write("show ip bgp summary\n")
        f.write("show bgp vrf all summary\n")
        f.write("show run | sec router bgp\n")
        f.write("show logging last 100\n\n")

        f.write("=" * 80 + "\n")
        f.write("ROLLBACK PROCEDURE\n")
        f.write("=" * 80 + "\n\n")

        for device in sorted(idle_df["device"].unique()):

            f.write(f"\nDEVICE: {device}\n")
            f.write("-" * 80 + "\n\n")

            device_df = idle_df[
                idle_df["device"] == device
            ]

            first_row = device_df.iloc[0]

            bgp_stmt = get_router_bgp(first_row)

            f.write("configure terminal\n")

            if not bgp_stmt:

                f.write(
                    "! WARNING - ASN NOT DISCOVERED\n"
                    "! MANUAL ROLLBACK REQUIRED\n\n"
                )

                continue

            f.write(f"{bgp_stmt}\n")

            for _, row in device_df.iterrows():

                f.write(
                    f" no neighbor {row['neighbor']} shutdown\n"
                )

            f.write(
                " exit\n"
                "end\n"
                "copy running-config startup-config\n\n"
            )

        f.write("=" * 80 + "\n")
        f.write("POST-ROLLBACK VALIDATION\n")
        f.write("=" * 80 + "\n\n")

        f.write("show bgp summary\n")
        f.write("show ip bgp summary\n")
        f.write("show bgp vrf all summary\n")

    print("\nMOP created successfully")
    print(f"Output file: {OUTPUT_MOP}")
    print(f"Idle neighbors found: {len(idle_df)}")


if __name__ == "__main__":
    main()