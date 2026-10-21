# Producing the inputs: the ASAGO pipeline

The ASAGO recommender uses the outputs of four earlier stages. This guide shows how to produce them, either by running the stages yourself or using the included scripts.

| Stage | Component | Input | Output |
|---|---|---|---|
| 1 | [asago-policy-mapper](https://github.com/asago-ai/asago-policy-mapper) | a policy document | `risk-extraction.json`: risks found in the policy |
| 2 | [asago-scenario-generator](https://github.com/asago-ai/asago-scenario-generator) | your use case description + `risk-extraction.json` | `scenario:v2:*.yaml`: threat scenarios for your agent |
| 3 | [asago-artifact-generator](https://github.com/asago-ai/asago-artifact-generator) | scenario YAMLs | `*-garak.json`: one attack transcript (garak probe) per scenario |
| 3b | garak evaluation (optional) | `*-garak.json` + your LLM endpoint | `baseline_summary.json`: which attacks succeed against your unprotected model |
| 4 | **asago-guardrails-recommender** (this repo) | the outputs of stages 2, 3 and 3b | rail recommendations and NeMo Guardrails configs per attack, ready to deploy and test on `/v1/checks` |

## Setup

All ASAGO components can be run from one checkout of [asago-examples](https://github.com/asago-ai/asago-examples), a uv workspace (Python 3.14) that installs each component and ships its inputs:

```bash
git clone https://github.com/asago-ai/asago-examples && cd asago-examples
uv sync --all-extras
```

## Step 1: choose a policy

- **Use an existing policy (skip the policy mapper).** asago-examples ships precomputed policy-mapper results in `asago-scenario-generator/inputs/risk-extractions/`: `risk-extraction-guy-nhs.json` (healthcare), `risk-extraction-fs-isac.json` (financial services) and `risk-extraction-amadeus.json` (travel). Go straight to step 2.
- **Run the policy mapper on a policy.** Use your own document, or one of the sample policies in `asago-policy-mapper/policy_examples/`. The policy mapper also needs a checkout of [ai-atlas-nexus](https://github.com/IBM/ai-atlas-nexus):
  ```bash
  cd asago-policy-mapper
  uv run asago-policy-mapper extract <policy.pdf> -o <out-dir> --nexus-base-dir <ai-atlas-nexus> \
    --base-url https://<your-endpoint>/v1 --model <model> --api-key <key>
  ```

## Step 2: generate scenarios for your use case

Write a `use_case.txt` describing your agent (purpose, users, tools, data), like [`examples/use_cases/`](../examples/use_cases/). Then:

```bash
cd asago-scenario-generator
uv run asago-scenario-generator generate --use-case @<use_case.txt> \
  --risk-extraction <risk-extraction.json> --sssom inputs/mappings/risk_to_category.sssom.tsv \
  --output-dir <my_results>/<use-case>/scenarios --generation-mode coverage
```

The model is set with `ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL`, `ASAGO_SCENARIO_GENERATOR_MODEL_NAME` and `ASAGO_SCENARIO_GENERATOR_API_KEY`; see the [scenario generator README](https://github.com/asago-ai/asago-scenario-generator).

## Step 3: generate the attacks (garak probes)

```bash
cd asago-artifact-generator
uv run asago-artifact-generator generate <my_results>/<use-case>/scenarios/<run>/scenarios/<scenario>.yaml \
  --force -v --output-dir <my_results>/<use-case>/artifacts
```

Run it once per scenario, or on the scenarios folder. The model is set with `OPENAI_BASE_URL`, `OPENAI_API_KEY` and `REDTEAM_MODEL`; see the [artifact generator README](https://github.com/asago-ai/asago-artifact-generator).

## Step 3b (optional): run the attacks against your endpoint

The garak evaluation replays each attack against your model and uses an LLM judge with the artifact's rubric to decide whether it succeeded. It writes `baseline_summary.json`. The evaluation code is in asago-examples [PR #35](https://github.com/asago-ai/asago-examples/pull/35) (branch `codex/end-to-end-demo`), not yet merged; check out that branch to use it, or use [`scripts/run_baseline_batch.py`](../scripts/run_baseline_batch.py) as below. The recommender works without this step.

## Step 4: put the results where the recommender reads them

```
<my_results>/
  baseline_summary.json                  # optional, step 3b
  <use-case>/scenarios/**/*.yaml         # step 2 output
  <use-case>/artifacts/**/*-garak.json   # step 3 output
```

- **One folder per use case**, named as you like; every folder is picked up.
- **`scenarios_exhaustive/` and `artifacts_exhaustive/`** are also accepted; [`examples/pipeline_results/`](../examples/pipeline_results/) uses them.
- **From each artifact** the recommender uses the transcript turns, `attack_turn_index` (which turn carries the attack), `injection_surface` and the narrative summary. From each scenario it uses the threat id and mechanism.

Then pass `<my_results>` to `recommend --pipeline-results`, as in [Deploy and test](deploy-and-test.md).

## Shortcut: run steps 1–3b with the scripts

[`scripts/`](../scripts/) automates steps 1–3b for several use cases and writes the layout above. It is the script we used for the sample data.

1. Clone asago-examples as above. For step 3b, check out the PR #35 branch (`git checkout codex/end-to-end-demo`).
2. Set the environment:
   ```bash
   export ASAGO_EXAMPLES_DIR=/path/to/asago-examples
   export LITELLM_ENDPOINT=https://<your-endpoint>/v1
   export LITELLM_API_KEY=<your-key>
   export AI_ATLAS_NEXUS_DIR=/path/to/ai-atlas-nexus      # only when running the policy mapper
   ```
3. Copy [`scripts/config.example.yaml`](../scripts/config.example.yaml) to `scripts/config.yaml` (gitignored). Per use case, set `use_case_file` and either `risk_extraction:` (an existing policy result, skips the policy mapper) or `policy_doc:` (runs the policy mapper).
4. Run from the repo root:
   ```bash
   uv run python scripts/run_pipeline.py --results-dir my_results           # steps 1-3; --use-case-id <id> for one
   uv run python scripts/run_baseline_batch.py --results-dir my_results \
     --target-model <your-model> --judge-model <judge-model>                # step 3b; --use-cases a b to limit
   ```
   Scenarios the artifact generator fails on are listed with their error output in `my_results/<use-case>/artifacts/failures.json`.

## Next

[Deploy and test](deploy-and-test.md) your recommendations.
