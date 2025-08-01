# 🔐 SSVC Copilot (Early Development)

**AI-augmented vulnerability prioritization using the Stakeholder-Specific Vulnerability Categorization (SSVC) framework**

## [Quickstart Guide](https://github.com/shaun89/ssvc-copilot/blob/main/quickstart.md)

---

## 🧠 What Is This?

SSVC Copilot is an experiment to make vulnerability triage more intelligent and actionable by combining:

- ✅ SSVC decision logic (stakeholder-specific vulnerability categorization)
- 🧠 LLM-based scoring assist (coming soon)
- 📊 Real-world system data like scan results, asset metadata, and threat intel

The goal: help IT and security teams prioritize what to patch and why — in a way that’s explainable, scalable, and useful.

---

## 🛠️ What This Project Will Do

- Ingest vulnerability scan data (e.g., OpenVAS or Nessus)
- Build a lightweight asset inventory from scan metadata
- Enrich CVEs with external data (e.g., EPSS, CISA KEV, CVSS)
- Apply SSVC decision rules (initially rule-based, later enhanced with AI)
- Output structured decisions (Act, Track, Defer) with justifications
- Eventually integrate LLMs to assist in evaluating exploitability and mission impact

- ---

## ✅ MVP Scope (v0.1)

This first version of SSVC Copilot is focused on demonstrating basic decision support using structured vulnerability data and rule-based logic. The MVP includes:

- ✅ Upload and normalize a Nessus scan file (CSV format)
- ✅ Generate a simple asset inventory from scan data
- ✅ Enrich CVEs with:
  - EPSS scores (static file or API)
  - CISA Known Exploited Vulnerabilities (KEV)
  - CVSS base scores
- ✅ Implement SSVC scoring logic using basic rules:
  - Based on exploitability, technical impact, and asset criticality
- ✅ Output a structured decision per CVE per asset:
  - `Act`, `Track`, or `Defer`
  - With justification fields
- ✅ Display decisions in a table (dashboard, SQL view, or exportable file)

The MVP will not include real-time threat detection, live network data analysis, or automated patch integrations. These are planned for future iterations.

---

## 🚧 Project Status: Just Getting Started

This project is under active initial development. Nothing is functional yet — just scaffolding and planning in progress.

- [ ] Upload and parse sample scan data
- [ ] Create basic asset inventory from scan
- [ ] Define SSVC scoring rules
- [ ] Join CVEs to enrichment data
- [ ] Build LLM prompt templates
- [ ] Create scoring logic and dashboard

---

## 📂 Project Structure (Planned)

---

## 🧠 SSVC Decision Points and MVP Data Sources

| Decision Point         | Description                                                                | MVP Data Source or Approximation                                |
|------------------------|----------------------------------------------------------------------------|------------------------------------------------------------------|
| **Exploit Status**     | Is the vulnerability being exploited?                                      | CISA KEV list, Exploit DB, PoC presence                          |
| **Technical Impact**   | How much does the vulnerability affect the system?                         | CVSS score and impact vector (CIA triad)                         |
| **Automatable**        | Can an attacker easily automate exploitation?                              | Public PoC scripts, EPSS score > threshold                       |
| **Mission Prevalence** | Is the affected asset widely deployed on critical missions?                | Asset role metadata (e.g., NetBox tag, manual override)          |
| **Public Safety Impact** | Could this endanger human life or public safety?                         | Asset type (e.g., medical, critical infrastructure), manual tag  |
| **Utility at Risk**    | Could this disrupt a utility or essential function?                        | Sector + asset criticality tag                       
## 🔭 Future Data Sources (Post-MVP)

While this MVP focuses on structured scan data and static enrichment, future versions of SSVC Copilot may incorporate:

- **Network traffic logs** (e.g., Zeek): to detect real-time exploit activity  
- **Suricata or IDS alerts**: to confirm active exploitation of known CVEs  
- **Vulnerability management systems** (e.g., OpenVAS, Tenable, Qualys): for live patch status  
- **System telemetry**: process/service data or behavioral anomalies  
- **Threat intelligence feeds**: dynamic intel for time-sensitive scoring  

These sources could enhance the **exploitability** and **mission impact** nodes of the SSVC decision tree, making the system more responsive and intelligent over time.


