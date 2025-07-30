import pandas as pd

def score_ssvc(row):
    exploit_status = row.get("kev_flag", False) or row.get("epss_score", 0) >= 0.8
    automatable = row.get("epss_score", 0) >= 0.5

    if exploit_status:
        return "Act"
    elif automatable:
        return "Track"
    else:
        return "Defer"

# Load uploaded CSV
input_file = "cve_enrichment.csv"
output_file = "ssvc_decisions.csv"

df = pd.read_csv(input_file)

# Add SSVC decision fields
df["ssvc_exploit_status"] = df.apply(lambda row: row.get("kev_flag", False) or row.get("epss_score", 0) >= 0.8, axis=1)
df["ssvc_automatable"] = df["epss_score"] >= 0.5
df["ssvc_technical_impact"] = "unknown"
df["ssvc_mission_prevalence"] = "unknown"
df["ssvc_decision"] = df.apply(score_ssvc, axis=1)

# Save to file
df.to_csv(output_file, index=False)
print("✅ SSVC decisions saved to ssvc_decisions.csv")
