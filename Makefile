.PHONY: run explain all

OPENVAS ?= data/openvas_scan.csv
NETBOX  ?= data/netbox_inventory.csv
OUT     ?= tmp/scored.csv

# Runs enrichment + scoring only
run:
	python scripts/run_pipeline.py --openvas $(OPENVAS) --netbox $(NETBOX) --out $(OUT)

# Runs Ollama explainer on an already-scored CSV
explain:
	python scripts/run_pipeline.py --scored-csv $(OUT) --out $(OUT) --ollama llama3 --ollama-out tmp/llm_summary.md --redact

# Runs both back-to-back
all:
	$(MAKE) run && $(MAKE) explain
