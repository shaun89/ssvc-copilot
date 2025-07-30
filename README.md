# 🔐 SSVC Copilot (Early Development)

**AI-augmented vulnerability prioritization using the Stakeholder-Specific Vulnerability Categorization (SSVC) framework**

---

## 🧠 What Is This?

SSVC Copilot is an experiment to make vulnerability triage more intelligent and actionable by combining:

- ✅ SSVC decision logic (stakeholder-specific vulnerability categorization)
- 🧠 LLM-based scoring assist (coming soon)
- 📊 Real-world system data like scan results, asset metadata, and threat intel

The goal: help IT and security teams prioritize what to patch and why — in a way that’s explainable, scalable, and useful.

---

## 🛠️ What This Project Will Do

- Ingest vulnerability scan data (e.g., Nessus)
- Build a lightweight asset inventory from scan metadata
- Enrich CVEs with external data (e.g., EPSS, CISA KEV, CVSS)
- Apply SSVC decision rules (initially rule-based, later enhanced with AI)
- Output structured decisions (Act, Track, Defer) with justifications
- Eventually integrate LLMs to assist in evaluating exploitability and mission impact

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

