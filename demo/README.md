# ASAGO Recommender Demo

Static replay of the policy-driven agentic red teaming pipeline: Policy Mapper (extracts risks from policy documents) → Scenario Generator → Artifact Generator → Recommender (suggests guardrails). All data is from pre-recorded runs (Gemma-4-26b for scenarios/artifacts; Qwen-3.8-27b for tagging). No live inference.

## Open

Open `index.html` directly in your browser, or serve with:

```sh
python3 -m http.server 8080
```

Any free port works. Then visit `http://localhost:8080/`.

## Rebuild Data

To regenerate `snapshot.json` and `snapshot.js` from pipeline outputs:

```sh
uv run asago-guardrails-recommender snapshot \
  --pipeline-results /path/to/pipeline_results \
  --run-dir /path/to/run1 \
  --catalog-dir /path/to/guardrail-catalog/rails \
  --policy 01_healthcare_us=/path/to/risk-extraction.json \
  --policy 02_banking_eu=/path/to/risk-extraction.json
```

Run `uv run asago-guardrails-recommender snapshot --help` for all options and defaults.
