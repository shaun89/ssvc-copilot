#!/usr/bin/env python3
"""
llm_explainer.py

Summarize a scored CSV using a local Ollama model.
- Creates the output directory if missing
- Optional redaction of hostnames/IPs
- Timeouts and basic retries for robustness

Usage:
  python scripts/llm_explainer.py \
    --model llama3 \
    --host http://localhost:11434 \
    --input tmp/scored.csv \
    --out tmp/llm_summary.md \
    --top-n 25 \
    --redact
"""

from __future__ import annotations
import argparse
import hashlib
import os
import re
import time
from pathlib import Path
from typing import List

import pandas as pd
import requests


def sha256_12(x: str) -> str:
    return hashlib.sha256(str(x).encode()).hexdigest()[:12]


def redact_df(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for col in ("host", "hostname", "device_name", "ip", "primary_ip4"):
        if col in out.columns:
            out[col] = out[col].astype(str).apply(sha256_12)
    return out


def build_prompt(df: pd.DataFrame, top_n: int) -> str:
    # Prioritize the most relevant columns for triage context
    cols = [c for c in df.columns if re.search(r"(cve|vuln|threat|epss|percentile|ssvc|priority|device|host|ip|kev)", c, re.I)]
    head = df[cols].head(top_n) if cols else df.head(top_n)
    csv_sample = head.to_csv(index=False)
    return (
        "You are assisting with SSVC-based vulnerability triage for a mixed IT/OT environment.\n"
        "Using the CSV rows below, produce a concise Markdown report (< ~500 words) with:\n"
        "1) Key themes (exploitation likelihood, KEV presence, EPSS distribution)\n"
        "2) Top 10 concrete remediation actions with one-line rationales\n"
        "3) High-impact assets or mission-critical areas (if visible)\n"
        "4) Assumptions and data gaps\n\n"
        "CSV sample:\n"
        f"{csv_sample}\n"
        "Be direct and prioritize actions that reduce risk fastest."
    )


def call_ollama(host: str, model: str, prompt: str, timeout_s: int = 60, max_retries: int = 2) -> str:
    url = host.rstrip("/") + "/api/generate"
    payload = {"model": model, "prompt": prompt, "stream": False}
    last_err = None

    for attempt in range(max_retries + 1):
        try:
            resp = requests.post(url, json=payload, timeout=timeout_s)
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "").strip()
        except Exception as e:
            last_err = e
            # Exponential-ish backoff
            time.sleep(1.0 * (attempt + 1))

    raise RuntimeError(f"Ollama call failed after {max_retries + 1} attempts: {last_err}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, required=True, help="Scored CSV input")
    ap.add_argument("--out", type=Path, required=True, help="Markdown output path")
    ap.add_argument("--model", type=str, default="llama3", help="Ollama model name (e.g., llama3)")
    ap.add_argument("--host", type=str, default=os.getenv("OLLAMA_HOST", "http://localhost:11434"), help="Ollama host URL")
    ap.add_argument("--top-n", type=int, default=25, help="Top N rows to include in the prompt")
    ap.add_argument("--redact", action="store_true", help="Redact hostnames/IPs in prompt")
    ap.add_argument("--timeout-s", type=int, default=60, help="HTTP timeout per request (seconds)")
    args = ap.parse_args()

    # Read input CSV
    if not args.input.exists():
        raise SystemExit(f"[!] Input CSV not found: {args.input}")
    df = pd.read_csv(args.input)

    # Optional redaction
    if args.redact:
        df = redact_df(df)

    # Build prompt and call Ollama
    prompt = build_prompt(df, args.top_n)
    md = call_ollama(args.host, args.model, prompt, timeout_s=args.timeout_s)

    # Ensure output directory exists and write file
    args.out.parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(md, encoding="utf-8")
    print(f"[✓] Wrote: {args.out}")


if __name__ == "__main__":
    main()
