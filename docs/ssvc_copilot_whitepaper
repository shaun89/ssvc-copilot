# Operationalizing SSVC: A Practical Framework for Enriched Vulnerability Prioritization

## Executive Summary

Modern organizations face a relentless stream of vulnerabilities from automated scans, yet most struggle to effectively prioritize which issues to fix first. Traditional severity scoring systems like CVSS offer limited context and often generate overwhelming volumes of "critical" results. This leads to patching delays, wasted effort, and increased exposure.

The Stakeholder-Specific Vulnerability Categorization (SSVC) framework, promoted by CISA and others, offers a more strategic approach to vulnerability decision-making. By incorporating contextual information such as exploitability, asset value, mission impact, and public exploitation status, SSVC enables organizations to make smarter, more risk-informed remediation plans.

This whitepaper outlines a practical method to operationalize SSVC using real-world enrichment data and an automated decision pipeline. We present a modular MVP architecture, realistic data sources, and a sample use case using a small cyber range.

## Introduction

Vulnerability management tools excel at finding flaws, but they rarely help organizations decide what to fix now versus what can wait. The reality is that time, talent, and patch windows are limited. SSVC addresses this by focusing on stakeholder-relevant context, transforming raw scan results into actionable prioritization.

However, applying SSVC in practice requires enrichment—pulling in data from asset inventories, threat intelligence, and organizational mission mapping. This whitepaper shows how to do that systematically and scalably.

## SSVC Overview

SSVC v2.0, as adopted by CISA, provides a decision tree framework based on five main decision points:

- **Exploitation Status**: Are there credible reports of exploitation in the wild?
- **Technical Impact**: What is the expected consequence of successful exploitation on the affected system?
- **Automatable**: Can the exploit be reliably automated (e.g., requires no user interaction)?
- **Mission Prevalence**: Is the affected system prevalent across or critical to the organization's key missions?
- **Public Well-Being Impact**: Would exploitation of this vulnerability impact public safety, health, or essential services?

The result is a prioritization decision (e.g., **Track**, **Attend**, **Act**, or **Defer**). Our goal is to automate and enrich these decision points.- **Exploitability**: Is there a known exploit in the wild? (informed by EPSS, KEV, GreyNoise, etc.)

- **Technical Impact**: Could the vulnerability cause significant technical harm?
- **Mission Impact**: Would this compromise affect key business functions?
- **Exposure/Utility**: Is the vulnerable service exposed or actively used?

The result is a prioritization decision (e.g., **Immediate**, **Scheduled**, **Ongoing Assessment**, **Defer**). Our goal is to automate and enrich these decision points.

## Realistic Enrichment Sources

| SSVC Decision Point      | Example Enrichment Sources                                                                                                       | Tooling                                                                                                                                                                                                                               |   |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | - |
| Exploitation Status      | CISA KEV Catalog, GreyNoise, FIRST EPSS, Recorded Future, CTI feeds                                                              | • CISA KEV: machine-readable CSV/API at [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)• GreyNoise: REST API• FIRST EPSS: JSON API & daily CSV downloads |   |
| Technical Impact         | CVSS Base Score (Impact subscore), vendor advisories, NVD entries                                                                | • NVD JSON feeds ([https://nvd.nist.gov/feeds/json-feed](https://nvd.nist.gov/feeds/json-feed))• Vendor advisory RSS/API                                                                                                              |   |
| Automatable              | EPSS scores, exploit proofs-of-concept, CVSS Exploitability metrics                                                              | • FIRST EPSS API & CSV• Exploit-DB RSS/API• CVE Details API (e.g., cvedetails.com API)                                                                                                                                                |   |
| Mission Prevalence       | Configuration Management Database (CMDB), asset inventory systems (e.g., NetBox), internal mission impact assessments            | • CMDB query via ServiceNow/other ITSM API• NetBox REST API• Custom CSV imports                                                                                                                                                       |   |
| Public Well-Being Impact | OT system classification, safety-critical asset tags, industry-specific regulatory mappings, mission-specific well-being context | • NetBox asset metadata fields• Custom AI enrichment via context prompts (e.g., LLM inference on asset tags and roles)                                                                                                                |   |

Each enrichment source supports a specific SSVC decision point. For example, KEV and EPSS contribute to exploitation status; CVSS Impact scores help estimate technical impact; and internal CMDB tagging supports mission prevalence analysis. Together, these data sources enable a more contextual and operationally relevant prioritization framework. a specific SSVC decision point. For example, KEV and EPSS contribute to exploitation status; CVSS Impact scores help estimate technical impact; and internal CMDB tagging supports mission prevalence analysis. Together, these data sources enable a more contextual and operationally relevant prioritization framework.

## Enrichment Pipeline Design

The enrichment pipeline follows a simple data flow:

1. **Ingest**: Parse raw scan data (CSV, JSON, Nessus, etc.)
2. **Normalize**: Map scan fields into a unified schema
3. **Enrich**: Join with KEV, EPSS, asset inventory, mission data
4. **Score**: Apply SSVC rules to produce prioritization
5. **Output**: Export results for teams, dashboards, or reports

This modular approach allows organizations to swap in new enrichments or update decision rules independently.

## Scoring & Prioritization

### Background and Rationale

The SSVC scoring system is built on the principle that vulnerability prioritization should balance *likelihood of exploitation* with *potential impact* and *organizational context*. Quantitative metrics (e.g., EPSS scores, CVSS Impact subscore) provide a data-driven baseline, while qualitative decision points (e.g., mission prevalence, public well-being impact) ensure the outcome aligns with stakeholder priorities and risk appetite. Thresholds are selected to distinguish clear-cut cases (e.g., high EPSS and critical assets) from those requiring further monitoring.

Key design considerations:

- **Separation of Likelihood and Impact**: Distinct decision points for exploitation status and technical impact prevent overemphasis on a single dimension.
- **Automatable Exploits**: Rapidly weaponized vulnerabilities (e.g., POCs, automation-friendly exploits) demand faster response.
- **Contextual Weighting**: Assets critical to core missions or public safety warrant escalated prioritization even if technical severity is moderate.
- **Simplicity and Auditability**: Clear, rule-based thresholds enable easy explanation to stakeholders and support compliance and auditing requirements.

These principles guide the thresholds and rule logic that follow below.

## Decision Point Assessment

The core of SSVC decisioning lies in mapping enriched inputs to a standardized set of actions: **Track**, **Attend**, **Act**, or **Defer**. Scoring combines both quantitative thresholds and qualitative decision rules for each SSVC decision point.

### Decision Point Assessment

| Decision Point           | Input Metric or Data                                  | Evaluation                                                                |
| ------------------------ | ----------------------------------------------------- | ------------------------------------------------------------------------- |
| Exploitation Status      | Presence in KEV, EPSS score, GreyNoise volume         | *High* if in KEV or EPSS > 0.9; *Medium* if EPSS > 0.5; *Low* otherwise   |
| Technical Impact         | CVSS Impact subscore, vendor severity advisory        | *High* for Impact ≥ 7.0; *Medium* for 4.0–6.9; *Low* for <4.0             |
| Automatable              | EPSS automation probability, exploit POC availability | *Yes* if EPSS > 0.7 or POC exists; *No* otherwise                         |
| Mission Prevalence       | Count of affected assets marked critical in CMDB      | *High* if > 10 critical assets; *Medium* if 3–10; *Low* if <3             |
| Public Well-Being Impact | Asset tags indicating safety or public services       | *High* if tagged safety-critical; *Medium* for regulated; *Low* otherwise |

### Rule-Based Scoring Logic

Below is an example pseudocode illustrating how inputs map to actions:

```python
# Example scoring function
def ssvc_decision(row):
    if row['Exploitation Status'] == 'High' and row['Technical Impact'] == 'High' and row['Public Well-Being Impact'] == 'High':
        return 'Act'
    elif row['Exploitation Status'] in ['High', 'Medium'] and row['Automatable'] and row['Mission Prevalence'] in ['High', 'Medium']:
        return 'Attend'
    elif row['Exploitation Status'] == 'Low' and row['Technical Impact'] == 'Low':
        return 'Defer'
    else:
        return 'Track'
```

### Action Mapping

- **Act**: Immediate remediation or compensating controls
- **Attend**: Schedule patching based on windows, track progress
- **Track**: Monitor for changes (exploit releases, asset changes)
- **Defer**: Document and re-evaluate periodically

### Auditability and Overrides

- Each decision is logged with input values for transparency.
- Analysts can override recommendations; overrides are tracked as annotations in the output report.

By structuring scoring this way, teams gain clear, actionable prioritization with both data-driven thresholds and human-readable rules.

## Conclusion

By combining SSVC with structured enrichment, organizations can cut through vulnerability noise and focus on what truly matters. This MVP offers a flexible, open-source path toward smarter, risk-aligned vulnerability remediation.

---

Let us know if you’d like access to the codebase, data templates, or example notebooks for your own implementation.

