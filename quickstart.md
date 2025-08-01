# SSVC Co-Pilot: Context-Aware Vulnerability Prioritization

A reproducible, open-source pipeline for turning raw vulnerability scans into actionable, business-aligned remediation plans using the latest CISA SSVC, EPSS, and KEV enrichment sources—plus your asset inventory.

---

## 🚀 Quickstart

**Requirements:**
- Python 3.8+
- Install dependencies:  
  `pip install -r requirements.txt` (includes `pandas`)

---

### 1. **Clone the Repo**

```bash
git clone git@github.com:shaun89/ssvc-copilot.git
cd ssvc-copilot
```

---

### 2. **Set Up Data Files**

Your `data/synthetic_data/` directory should contain:

- `openvas_scan.csv` — Export from OpenVAS or a synthetic scan report (example included)
- `netbox_inventory.csv` — Export from NetBox or a synthetic inventory (example included)

**You do NOT need to download enrichment sources manually.**  
`get_epss_enrichment.py` fetches the latest feeds live from the internet.

---

### 3. **Run the Pipeline**

This will:
- Join scan with inventory
- Enrich with the latest EPSS & CISA KEV data
- Score/prioritize each vulnerability with SSVC logic

```bash
python3 scripts/run_pipeline.py \
  --openvas data/synthetic_data/openvas_scan.csv \
  --netbox data/synthetic_data/netbox_inventory.csv \
  --tmpdir tmp/
```

Outputs will be in `tmp/`:
- `enriched_scan.csv`
- `enriched_with_epss.csv`
- `ssvc_scored.csv` (your main results)

---

### 4. **Review Your Results**

Open `tmp/ssvc_scored.csv` in Excel, VSCode, or any spreadsheet tool.

Key columns:
- `device_name` (from NetBox)
- `cve_id`
- `epss`, `percentile`
- `kev_flag`
- `ssvc_decision` (Act, Attend, Track, Defer)

---

## 🧩 How it Works

### Pipeline Steps:
1. **Scan & Asset Join:**  
   Links vulnerabilities to assets using IP address.
2. **Enrichment:**  
   Pulls EPSS (exploit prediction) and KEV (known-exploited) data for each CVE.
3. **Scoring:**  
   Applies CISA SSVC v2.0 logic for business-aligned, risk-based prioritization.

---

## 🛠️ File/Folder Map

| File/Folder                                | What goes here                              |
|--------------------------------------------|---------------------------------------------|
| `data/synthetic_data/openvas_scan.csv`     | Your OpenVAS CSV scan (input or synthetic)  |
| `data/synthetic_data/netbox_inventory.csv` | Your NetBox CSV (input or synthetic)        |
| `tmp/`                                     | Outputs (auto-generated, ignored by git)    |
| `scripts/`                                 | All pipeline Python scripts                 |
| `scripts/get_epss_enrichment.py`           | Enrichment script (fetches EPSS & KEV)      |
| `scripts/join_openvas_to_netbox.py`        | Asset-Scan merge script                     |
| `scripts/score_ssvc.py`                    | SSVC logic/scoring script                   |

---

## 🕹️ Customizing & Troubleshooting

- **Use your own data:**  
  Replace the CSVs in `data/synthetic_data/`.

- **EPSS feed errors?**  
  The script downloads from [EmpiricalSecurity EPSS Mirror](https://epss.empiricalsecurity.com/epss_scores-current.csv.gz).  
  If this changes, edit the `EPSS_URL` variable in `get_epss_enrichment.py`.

- **Problems merging?**  
  Check all input CSVs have a `cve` or `cve_id` column (case-insensitive).
  Use the debug-enabled scripts to print DataFrame headers.

---

## 📊 SSVC Decision Logic

The pipeline will categorize vulnerabilities as:
- **Act:** Patch or mitigate immediately
- **Attend:** Schedule for remediation soon
- **Track:** Monitor for escalation or exploit activity
- **Defer:** De-prioritize for now

See [`scripts/score_ssvc.py`](scripts/score_ssvc.py) to adjust the rules.

---

## 🔗 Data Sources

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [EPSS Data (Empirical Security Mirror)](https://epss.empiricalsecurity.com/epss_scores-current.csv.gz)
- [SSVC v2.0 Guidance PDF](https://www.cisa.gov/sites/default/files/publications/Stakeholder-Specific-Vulnerability-Categorization-SSVC_1.pdf)

---

---

## 📝 License

This project is pending official license. 

---

**Questions or want to add a new data source?  
Open an issue or email the repo owner!**
