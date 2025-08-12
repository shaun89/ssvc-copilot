import subprocess
import argparse
import os

def run_step(description, command):
    print(f"\n[→] {description}")
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        raise RuntimeError(f"❌ Step failed: {description}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run full SSVC enrichment and scoring pipeline.")
    parser.add_argument("--openvas", required=True, help="Path to OpenVAS scan CSV")
    parser.add_argument("--netbox", required=True, help="Path to NetBox inventory CSV")
    parser.add_argument("--tmpdir", default="tmp", help="Directory to store intermediate outputs")
    args = parser.parse_args()

    os.makedirs(args.tmpdir, exist_ok=True)

    joined_path = os.path.join(args.tmpdir, "enriched_scan.csv")
    epss_path = os.path.join(args.tmpdir, "enriched_with_epss.csv")
    final_path = os.path.join(args.tmpdir, "ssvc_scored.csv")

    # Step 1: Join OpenVAS + NetBox
    run_step(
        "Joining OpenVAS scan with NetBox inventory",
        f"python3 scripts/join_openvas_to_netbox.py --openvas {args.openvas} --netbox {args.netbox} --output {joined_path}"
    )

    # Step 2: Enrich with EPSS + KEV
    run_step(
        "Enriching scan with EPSS (and KEV if integrated)",
        f"python3 scripts/get_epss_enrichment.py --input {joined_path} --output {epss_path}"
    )

    # Step 3: Score using SSVC logic
    run_step(
        "Scoring with SSVC decision logic",
        f"python3 scripts/score_ssvc.py --input {epss_path} --output {final_path}"
    )

    # Add this import at the top
    from scripts import llm_explainer

    # Add this block at the end of the pipeline (or wherever fits best)
    print("[STEP 4] Generating SSVC explanations via LLM")
    llm_explainer.run(
        input_csv='tmp/ssvc_scored.csv',
        output_csv='tmp/ssvc_scored_with_llm.csv',
        limit=10  # adjust or remove for full dataset
)

    print(f"\n✅ Pipeline complete! Final SSVC output: {final_path}")
