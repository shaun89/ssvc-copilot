import pandas as pd
import argparse

def join_openvas_with_netbox(openvas_path, netbox_path, output_path):
    # Load files
    openvas_df = pd.read_csv(openvas_path)
    netbox_df = pd.read_csv(netbox_path)

    # Normalize IP fields
    openvas_df["Host"] = openvas_df["Host"].str.strip()
    netbox_df["IP Address"] = netbox_df["IP Address"].str.strip()

    # Merge on IP
    merged_df = openvas_df.merge(
        netbox_df,
        left_on="Host",
        right_on="IP Address",
        how="left"
    )

    # Rename and select final output columns
    merged_df = merged_df.rename(columns={
        "Name_x": "Vulnerability Name",
        "Name_y": "Device Name"
    })

    output_columns = [
        "Device Name", "Device Role", "Device Type", "Manufacturer", "cf_mission_prevalence",
        "Host", "Port", "Threat", "CVE", "Vulnerability Name", "Summary", "Timestamp"
    ]
    merged_df[output_columns].to_csv(output_path, index=False)
    print(f"[✓] Enriched scan saved to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Join OpenVAS scan with NetBox asset data")
    parser.add_argument("--openvas", required=True, help="Path to OpenVAS scan CSV")
    parser.add_argument("--netbox", required=True, help="Path to NetBox inventory CSV")
    parser.add_argument("--output", required=True, help="Path to output enriched CSV")

    args = parser.parse_args()
    join_openvas_with_netbox(args.openvas, args.netbox, args.output)
