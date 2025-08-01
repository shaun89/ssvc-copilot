import pandas as pd
import argparse

def score_row(row):
    exploit_status = row.get("kev_flag", False) or row.get("epss", 0) >= 0.8
    automatable = row.get("epss", 0) >= 0.5
    mission = str(row.get("cf_mission_prevalence", "")).lower()

    if exploit_status and mission == "essential":
        return "Act"
    elif exploit_status or (automatable and mission in ["support", "essential"]):
        return "Attend"
    elif row.get("epss", 0) < 0.1 and mission == "minimal":
        return "Defer"
    else:
        return "Track"

def main(input_path, output_path):
    df = pd.read_csv(input_path)
    df["ssvc_decision"] = df.apply(score_row, axis=1)
    df.to_csv(output_path, index=False)
    print(f"[✓] SSVC decisions written to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Score scan data using SSVC rules")
    parser.add_argument("--input", required=True, help="Path to enriched input CSV")
    parser.add_argument("--output", required=True, help="Path to save output with SSVC decisions")
    args = parser.parse_args()

    main(args.input, args.output)
