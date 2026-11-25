# ASAGO Recommender Demo

Static replay of the policy-driven agentic red teaming pipeline: Policy Mapper (extracts risks from policy documents) → Scenario Generator → Artifact Generator → Guardrail Recommender (suggests and tests guardrails). All data is from one recorded run on two mock use cases (Gemma-4-26b for scenarios, artifacts and the target model's replies; Qwen-3.8-27b for tagging and the self-check judges). No live inference.

## Open

Open `index.html` directly in your browser, or serve with:

```sh
python3 -m http.server 8080
```

Any free port works. Then visit `http://localhost:8080/`.

Pick a use case at the top, then click **Run all** (or **Run** per stage). The attack you select stays selected across stages.

The Guardrail Recommender stage has five tabs:

- **Tag signals:** the signals found in the selected attack.
- **Candidate pool:** the catalog rails that match those signals.
- **Select minimal config:** Option 1 and Option 2 with their input and output rails, the NeMo config, and the use case's self-check policy.
- **Test on NeMo /v1/checks:** what blocked the attack in each option, and under **Results for this use case** the per-option totals and the Input rails and Output rails tables (how often each rail ran and blocked). Shared NeMo flows, such as the Presidio PII flow, are labelled as such.
- **Benign requests:** false positives: the benign totals and the rails that blocked benign requests.

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

Benign requests and replies are read from `examples/benign_requests` (override with `--benign-dir`). Test results come from the run dir's `output_test_results.json`.

Pointing this at `examples/pipeline_results` and `examples/run1` gives a partial demo (no policy without `--policy`, no NeMo configs, smaller funnels). The shipped `data/` was built from the full pipeline outputs of the sample run, not from `examples/` alone: the Scenario Generator and Artifact Generator tabs count every generated scenario and artifact (including attacks that failed at baseline and the scenario run's admission files), and `examples/` keeps only the 58 attacks that got through at baseline. The Recommender tabs show the same data as `examples/run1`.

Run `uv run asago-guardrails-recommender snapshot --help` for all options and defaults.
