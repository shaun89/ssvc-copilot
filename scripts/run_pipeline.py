#!/usr/bin/env python3
"""
run_pipeline.py

Join OpenVAS + NetBox -> enrich with EPSS/KEV (your existing script) ->
score with SSVC (your existing script) -> optional Ollama summary.

Example:
  python scripts/run_pipeline.py \
    --openvas data/openvas_scan.csv \
    --netbox data/netbox_inventory.csv \
    --out tmp/scored.csv \
    --ollama llama3 --ollama-out tmp/llm_summary.md --redact
"""

from __future__ import annotations
import argparse
import hashlib
import os
import re
import sys
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

import pandas as pd


# ---------------- Utility functions ----------------

def run_cmd(cmd: List[str], fail_msg: str = "Command failed") -> None:
    """Run a subprocess and fail with captured output if non-zero."""
    print(f"[→] {' '.join(map(str, cmd))}")
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        if proc.stdout:
            print(proc.stdout)
        sys.exit(f"[!] {fail_msg}: {' '.join(map(str, cmd))}")
    if proc.stdout:
        print(proc.stdout.strip())


def safe_read_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        sys.exit(f"[!] Missing CSV: {path}")
    try:
        return pd.read_csv(path)
    except Exception as e:
        sys.exit(f"[!] Failed to read CSV {path}: {e}")


def write_csv(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
    print(f"[✓] Wrote {len(df):,} rows -> {path}")


def _normalize_cols(df: pd.DataFrame) -> pd.DataFrame:
    """Lowercase, trim, and replace non-alnum with underscores for all column names."""
    df = df.copy()
    norm = {}
    for c in df.columns:
        nc = re.sub(r"[^a-z0-9]+", "_", c.strip().lower())
        norm[c] = nc.strip("_")
    return df.rename(columns=norm)


def _extract_ip(series: pd.Series) -> pd.Series:
    """Take '10.0.0.1/24' -> '10.0.0.1'. Leave hostnames unchanged."""
    return series.astype(str).str.split("/").str[0].str.strip()


def _pick(colnames: list[str], df: pd.DataFrame) -> Optional[str]:
    for c in colnames:
        if c in df.columns:
            return c
    return None


def join_openvas_netbox(openvas_csv: Path, netbox_csv: Path) -> pd.DataFrame:
    """Case-insensitive, robust join between OpenVAS and NetBox exports."""
    ov_raw = safe_read_csv(openvas_csv)
    nb_raw = safe_read_csv(netbox_csv)

    ov = _normalize_cols(ov_raw)
    nb = _normalize_cols(nb_raw)

    # NetBox "IP Address" -> ip_address -> primary_ip4 (strip CIDR)
    if "ip_address" in nb.columns and "primary_ip4" not in nb.columns:
        nb["primary_ip4"] = _extract_ip(nb["ip_address"])

    # Candidate join keys after normalization
    ov_candidates = ["device_name", "hostname", "host", "ip"]
    nb_candidates = ["device_name", "name", "hostname", "primary_ip4", "primary_ip"]

    ov_key = _pick(ov_candidates, ov)
    nb_key = _pick(nb_candidates, nb)

    if not ov_key or not nb_key:
        raise SystemExit(
            "[!] Could not find join keys after normalization.\n"
            f"    OpenVAS columns: {list(ov.columns)}\n"
            f"    NetBox  columns: {list(nb.columns)}\n"
            "    Need one of OpenVAS [device_name|hostname|host|ip] and one of NetBox [device_name|name|hostname|primary_ip4|primary_ip]"
        )

    # Prepare join keys (strip + lowercase). If IP on NB side, ensure CIDR is stripped.
    ov["_join_key"] = ov[ov_key].astype(str).str.strip().str.lower()
    if nb_key in ("primary_ip4", "primary_ip", "ip_address"):
        nb["_join_key"] = _extract_ip(nb[nb_key]).str.lower()
    else:
        nb["_join_key"] = nb[nb_key].astype(str).str.strip().str.lower()

    merged = ov.merge(
        nb.drop_duplicates("_join_key"),
        on="_join_key",
        how="left",
        suffixes=("", "_nb"),
    ).drop(columns=["_join_key"])

    print(f"[i] Joining OpenVAS.{ov_key} -> NetBox.{nb_key}")
    print(f"[✓] Merged rows: {len(merged):,} | Matches: {merged[nb_key].notna().sum():,}")

    return merged


def sha256_12(x: str) -> str:
    return hashlib.sha256(x.encode()).hexdigest()[:12]


def redact_df(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for col in ("host", "hostname", "device_name", "ip", "primary_ip4"):
        if col in out.columns:
            out[col] = out[col].astype(str).apply(sha256_12)
    return out


# ---------------- Main pipeline ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--openvas", type=Path, help="OpenVAS CSV input")
    ap.add_argument("--netbox", type=Path, help="NetBox CSV input")
    ap.add_argument("--out", type=Path, required=True, help="Output scored CSV path")

    # Skip core pipeline if you already have a scored CSV and only want LLM
    ap.add_argument("--scored-csv", type=Path, default=None, help="Use existing scored CSV and skip core steps")

    # Optional Ollama step
    ap.add_argument("--ollama", type=str, default=None, help="Ollama model name (e.g., llama3). If set, runs summary.")
    ap.add_argument("--ollama-out", type=Path, default=Path("tmp/llm_summary.md"), help="Markdown summary output path")
    ap.add_argument("--ollama-host", type=str, default=os.getenv("OLLAMA_HOST", "http://localhost:11434"), help="Ollama host URL")
    ap.add_argument("--top-n", type=int, default=25, help="Top N rows to include in the summary prompt")
    ap.add_argument("--redact", action="store_true", help="Redact hostnames/IPs in prompts/summary")

    args = ap.parse_args()

    scored_csv = args.scored_csv

    if not scored_csv:
        if not args.openvas or not args.netbox:
            ap.error("--openvas and --netbox are required unless --scored-csv is provided.")

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            merged_csv = td / "merged.csv"
            enriched_csv = td / "enriched.csv"

            # Step 1: Join
            merged = join_openvas_netbox(args.openvas, args.netbox)
            write_csv(merged, merged_csv)

            # Step 2: Enrich with EPSS/KEV (use same interpreter)
            enrich_cmd = [sys.executable, "scripts/get_epss_enrichment.py", "--in", str(merged_csv), "--out", str(enriched_csv)]
            run_cmd(enrich_cmd, "EPSS enrichment failed")

            # Step 3: Score with SSVC (use same interpreter)
            score_cmd = [sys.executable, "scripts/score_ssvc.py", "--in", str(enriched_csv), "--out", str(args.out)]
            run_cmd(score_cmd, "SSVC scoring failed")

            scored_csv = args.out
            print(f"[✓] Scored CSV ready: {scored_csv}")

    # Step 4: Optional Ollama summary using your llm_explainer.py (use same interpreter)
    if args.ollama:
        cmd = [
            sys.executable, "scripts/llm_explainer.py",
            "--model", args.ollama,
            "--input", str(scored_csv),
            "--out", str(args.ollama_out),
            "--host", args.ollama_host,
            "--top-n", str(args.top_n),
        ]
        if args.redact:
            cmd.append("--redact")

        run_cmd(cmd, "LLM explainer failed")
        print(f"[✓] LLM summary written: {args.ollama_out}")


if __name__ == "__main__":
    main()
