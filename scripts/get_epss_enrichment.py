#!/usr/bin/env python3
import pandas as pd
import requests
import gzip
from io import BytesIO

def normalize_and_detect_cve(df, df_name):
    # Normalize column names: strip whitespace, lowercase
    df.columns = df.columns.str.strip().str.lower()
    # Detect first column containing 'cve'
    cve_cols = [c for c in df.columns if 'cve' in c]
    if not cve_cols:
        raise RuntimeError(f"No CVE column found in {df_name}; columns are {df.columns.tolist()}")
    # Rename to cve_id
    df.rename(columns={cve_cols[0]: 'cve_id'}, inplace=True)
    print(f"{df_name} columns after normalize →", df.columns.tolist())
    return df

def main():
    print("✅ Script started...")

    # === Download & load EPSS data (gzipped CSV) ===
    print("📥 Downloading EPSS data...")
    epss_url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    resp = requests.get(epss_url, headers={"User-Agent": "Mozilla/5.0"})
    resp.raise_for_status()
    with gzip.open(BytesIO(resp.content), 'rt') as f:
        epss = pd.read_csv(f, comment='#', low_memory=False)
    epss = normalize_and_detect_cve(epss, "EPSS")

    # === Download & load CISA KEV data (JSON) ===
    print("📥 Downloading CISA KEV data...")
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_raw = requests.get(kev_url, headers={"User-Agent": "Mozilla/5.0"}).json()
    kev = pd.DataFrame(kev_raw.get("vulnerabilities", []))
    kev = normalize_and_detect_cve(kev, "KEV")
    kev['kev_flag'] = True

    # === Merge datasets ===
    print("🔗 Merging EPSS and KEV on 'cve_id'...")
    merged = pd.merge(epss, kev[['cve_id', 'kev_flag']], on='cve_id', how='left')
    merged['kev_flag'] = merged['kev_flag'].fillna(False)

    # === Select & rename final fields ===
    enrichment = merged[['cve_id', 'epss', 'percentile', 'kev_flag']].copy()
    enrichment = enrichment.rename(columns={'epss': 'epss_score'})

    # === Save output ===
    out_path = "cve_enrichment.csv"
    enrichment.to_csv(out_path, index=False)
    print(f"✅ Done! Saved {len(enrichment)} rows to {out_path}")

if __name__ == "__main__":
    main()
