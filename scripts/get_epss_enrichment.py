#!/usr/bin/env python3
import pandas as pd
import argparse
import urllib.request
import gzip
import io

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def normalize(df):
    df.columns = [c.lower().strip().replace(" ", "_") for c in df.columns]
    return df

def load_epss():
    print("📥 Downloading EPSS data...")
    with urllib.request.urlopen(EPSS_URL) as resp:
        compressed = io.BytesIO(resp.read())
    with gzip.open(compressed, mode='rt', encoding='utf-8') as f:
        lines = f.read().splitlines()
    header_idx = None
    for idx, line in enumerate(lines):
        if line.lower().startswith("cve,"):
            header_idx = idx
            break
    if header_idx is None:
        raise ValueError("Failed to locate EPSS CSV header row")
    csv_data = "\n".join(lines[header_idx:])
    epss_df = pd.read_csv(io.StringIO(csv_data), low_memory=False)
    print(f"EPSS RAW COLUMNS: {epss_df.columns.tolist()}")
    epss_df = normalize(epss_df)
    print(f"EPSS NORMALIZED COLUMNS: {epss_df.columns.tolist()}")
    print("EPS dataframe preview:\n", epss_df.head())
    if 'cve' in epss_df.columns:
        epss_df = epss_df.rename(columns={'cve': 'cve_id'})
    return epss_df[['cve_id', 'epss', 'percentile']]

def load_kev():
    print("📥 Downloading CISA KEV data...")
    kev_json = pd.read_json(KEV_URL)
    kev = pd.json_normalize(kev_json['vulnerabilities'])
    kev = normalize(kev)
    kev['kev_flag'] = True
    if 'cveid' in kev.columns:
        kev = kev.rename(columns={'cveid': 'cve_id'})
    elif 'cve_id' not in kev.columns:
        raise KeyError("Expected 'cveid' or 'cve_id' in KEV data")
    print(f"KEV columns after normalize → {list(kev.columns)}")
    print("KEV dataframe preview:\n", kev.head())
    return kev[['cve_id', 'kev_flag']]

def main(input_path, output_path):
    print("✅ Starting enrichment script...")

    scan_df = pd.read_csv(input_path)
    scan_df = normalize(scan_df)
    print("SCAN columns after normalize:", scan_df.columns.tolist())
    print("SCAN dataframe preview:\n", scan_df.head())

    epss = load_epss()
    kev = load_kev()
    print("Type of epss:", type(epss))
    print("Type of kev:", type(kev))
    print("EPS dataframe shape:", epss.shape)
    print("KEV dataframe shape:", kev.shape)

    # Try to merge on the right column
    merge_key = None
    if "cve_id" in scan_df.columns:
        merge_key = "cve_id"
    elif "cve" in scan_df.columns:
        scan_df = scan_df.rename(columns={"cve": "cve_id"})
        merge_key = "cve_id"
    else:
        raise KeyError("Neither 'cve_id' nor 'cve' found in scan data columns.")

    merged = epss.merge(kev, on='cve_id', how='left')
    merged['kev_flag'] = merged['kev_flag'].fillna(False)

    print("🔗 Merging enrichment into scan data...")
    result = scan_df.merge(merged, on=merge_key, how='left')

    result['epss'] = result['epss'].fillna(0.0)
    result['percentile'] = result['percentile'].fillna(0.0)
    result['kev_flag'] = result['kev_flag'].fillna(False)

    result.to_csv(output_path, index=False)
    print(f"✅ Enriched scan saved to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enrich scan with EPSS+KEV")
    parser.add_argument("--input", required=True, help="Path to OpenVAS scan CSV")
    parser.add_argument("--output", required=True, help="Path to write enriched scan CSV")
    args = parser.parse_args()
    main(args.input, args.output)
