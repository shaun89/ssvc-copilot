import pandas as pd
import ollama

def run(input_csv, output_csv, limit=None):
    print(f"[→] Running LLM explainer on: {input_csv}")

    try:
        df = pd.read_csv(input_csv)
    except FileNotFoundError:
        print(f"❌ File not found: {input_csv}")
        return

    if limit:
        df = df.head(limit)

    prompt_template = """
You are an expert in SSVC vulnerability analysis.

Given the following vulnerability:
- CVE: {cve}
- Asset: {asset}
- Mission Impact: {mission_impact}
- KEV: {kev}
- EPSS: {epss}
- Exposure: {exposure}
- Patch Available: {patch}
- SSVC Decision: {ssvc}

Explain in 2-3 sentences why this SSVC decision is appropriate.
Then, suggest an appropriate remediation step.
"""

    def get_llm_explanation(row):
        prompt = prompt_template.format(
            cve=row.get('cve', 'Unknown'),
            asset=row.get('device_name', 'Unknown'),
            mission_impact=row.get('cf_mission_prevalence', 'Unknown'),
            kev=row.get('kev_flag', 'Unknown'),
            epss=row.get('epss', 'Unknown'),
            exposure=row.get('threat', 'Unknown'),
            patch='Unknown',
            ssvc=row.get('ssvc_decision', 'Unknown')
        )
        try:
            response = ollama.chat(
                model='mistral',
                messages=[{"role": "user", "content": prompt}]
            )
            return response['message']['content']
        except Exception as e:
            return f"[LLM Error] {str(e)}"

    print("[ℹ️] Generating LLM explanations...")
    df['llm_explanation'] = df.apply(get_llm_explanation, axis=1)
    df.to_csv(output_csv, index=False)
    print(f"[✓] LLM explanations saved to: {output_csv}")
