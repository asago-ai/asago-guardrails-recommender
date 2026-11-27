# Recommend, deploy and test

This guide shows how to run the recommender on your attacks, deploy the generated configs, and test them against a NeMo Guardrails server.

## Prerequisites

You have produced the inputs using the [ASAGO pipeline](asago-pipeline.md). Now you need an LLM endpoint and a NeMo Guardrails server to test on.

### Connect your LLM endpoint

The LLM is used in two places:
- the **tagger**, which runs on your machine and labels each attack's signals;
- the **LLM-judge rail** (`self_check_input_policy`), which runs inside NeMo.

Any OpenAI-compatible `/chat/completions` endpoint works, for example a LiteLLM gateway, vLLM, or OpenAI.

```bash
export LITELLM_BASE_URL=https://<your-endpoint>/v1   # or pass --llm-base-url
export LITELLM_API_KEY=<your-key>                    # OPENAI_API_KEY also works
```

The same URL is written into the LLM-judge config, so it must be reachable from the NeMo server as well as from your machine.

| Flag (on `recommend`) | Purpose |
|---|---|
| `--tagger-model` | Model used for tagging (default `qwen-3.8-27b`) |
| `--guard-model` | Model used by the LLM-judge rail (default `qwen-3.8-27b`) |
| `--no-thinking-kwargs` | Don't send `chat_template_kwargs.enable_thinking=false`. That setting is for vLLM-served reasoning models such as Qwen; use this flag for other providers |

### Set up a NeMo Guardrails server for `/v1/checks`

Every recommendation is tested by sending the attack to a NeMo Guardrails server's `/v1/checks` endpoint, selecting the config with `guardrails.config_id`. The server needs:

- **A NeMo Guardrails server build with these packages:** `nemoguardrails` including `nemoguardrails.http`, `presidio-analyzer` and `torch`. We use `quay.io/trustyai/nemo-guardrails-server@sha256:bf08994e…`, the default in `src/asago_guardrails_recommender/deploy.py`. The OpenShift AI 3.5.1 image lacks `nemoguardrails.http` and can't load the catalog's `actions.py`.
- **Egress to Hugging Face** on first use. The classifier rails download `RedHatAI/deberta-v3-base-prompt-injection-v2` and `RedHatAI/granite-guardian-hap-125m`, which takes about a minute.
- **The LLM key** as an environment variable (`OPENAI_API_KEY`) for the LLM-judge rail. `/v1/checks` doesn't forward request headers, so the key can't be sent per request.
- **The generated configs** from `output/<run-id>/server_configs/`, one folder per `config_id`.

There are two ways to get one:

- **On OpenShift or Kubernetes (recommended):** `asago-guardrails-recommender deploy` writes the manifests for you, as shown in [step 3 of Run it](#run-it-on-your-use-case). Create the key secret once:
  ```bash
  oc -n <ns> create secret generic litellm-master-key --from-literal=master-key=<your-key>
  ```
- **On an existing NeMo server:** mount or copy `output/<run-id>/server_configs/` as its config directory, set `OPENAI_API_KEY`, and pass its URL to `test --nemo-url`.

## Run it on your use case

Steps 1 and 2 only write files. Steps 3 onwards change the cluster.

**1. Install.**

```bash
uv sync
```

**2. Recommend.**

```bash
uv run asago-guardrails-recommender recommend --pipeline-results <my_results> --run-id <run-id>
```

**3. Build the manifests.**

```bash
uv run asago-guardrails-recommender deploy --run-dir output/<run-id> --mode standalone --namespace <ns>
```

- `--image` overrides the default server image.
- `--used-only` deploys only the configs that tests send requests to (each option's config plus the single-rail configs in its test plan). Options with the same rails share one config named `opt-<hash>[-out]`, so this is usually a small set.
- `--mode operator` writes a `NemoGuardrails` custom resource instead. It needs the TrustyAI operator and an image that can load the catalog.

**4. Deploy and wait for readiness.**

```bash
oc apply -f output/<run-id>/deploy-standalone.yaml
oc -n <ns> rollout status deployment/asago-rec
```

**5. Test.**

```bash
oc -n <ns> port-forward svc/asago-rec 8000:80 &
uv run asago-guardrails-recommender test --run-dir output/<run-id> --nemo-url http://localhost:8000
```

`--dry-run` writes the request bodies and prints curl commands without sending anything. A test counts as **blocked** when NeMo returns `status: blocked`.

**6. Summarize.**

```bash
uv run asago-guardrails-recommender test --run-dir output/<run-id> --summarize
```

The first two tables come from the run dir's own result files and reconcile with them: per option rank (attacks tested, blocked at input, blocked at output among attacks not blocked at input, attack success; errors excluded), and per rail id (attack catches at input and at output, benign blocks at input and output). NeMo flow names are mapped to catalog rail ids. Flows shared by several cards (for example all PII cards, or the three regex cards) are reported under the card type (`sensitive_data_detection`, `regex_detection`). The last section is the efficacy store, which aggregates all runs and is not limited to the run dir.

## Output rails

With `--output-rails`, the recommender also selects output rails per option, from the attack's signals: injection regexes on the reply, Presidio for PII and exfiltration, YARA and HAP for harmful payloads, and the self-check output judge for action and disclosure signals. See [design.md section 8](design.md#8-output-rails) for the selection rules.

**Recommend with output rails:**

```bash
uv run asago-guardrails-recommender recommend --output-rails --pipeline-results <my_results> --run-id <run-id>
```

Options with output rails get a combined input + output server config under `server_configs/`. Configs are named by a hash of their content (`opt-<hash>-out`), so options with the same rails share one config.

**Deploy:**

Run the same deploy step. `--used-only` deploys only the configs that the recommendations use, not one per catalog rail:

```bash
uv run asago-guardrails-recommender deploy --run-dir output/<run-id> --mode standalone --namespace <ns> --used-only
```

**Test with output rails:**

For each option with output rails, `test --with-output` runs the attack, calls the LLM, and tests the output check:

```bash
uv run asago-guardrails-recommender test --run-dir output/<run-id> --nemo-url http://localhost:8000 --with-output --dry-run
uv run asago-guardrails-recommender test --run-dir output/<run-id> --nemo-url http://localhost:8000 --with-output
```

Results are in `<run-dir>/output_test_results.json` (includes model replies).

To test output rails on the reply the baseline actually judged, instead of a fresh one, pass the replies
extracted from the garak reports. No LLM call is made; attack success comes from the baseline outcome.

```bash
python scripts/extract_baseline_replies.py --baseline-dir <baseline results> --out <results>/baseline_replies.json
uv run asago-guardrails-recommender test --run-dir output/<run-id> --nemo-url http://localhost:8000 --with-output \
  --baseline-replies <results>/baseline_replies.json
```

Most agentic replies are tool calls with no text. The output rails see a text rendering: the reply text, then one
`[tool call] <name>(<arguments>)` line per call.

| Outcome | Meaning |
|---|---|
| `blocked_input` | Input rails blocked the attack |
| `blocked_output` | Output rails blocked the reply |
| `model_refused` | The LLM refused the attack |
| `attack_succeeded` | Neither input nor output rails blocked it |

## Benign requests (false positives)

Attack tests only show that a config blocks attacks. To check that it does not block normal use, run benign requests through the same configs:

```bash
uv run asago-guardrails-recommender test --run-dir output/<run-id> --nemo-url http://localhost:8000 --benign-requests examples/benign_requests
```

`--benign-requests DIR` reads one `<use_case>.yaml` per use case (the file name must match the `use_case` field). Each request has `kind: plain` or `kind: borderline`. Use `--dry-run` to count the calls without sending them.

Which configs are tested: every distinct `config_id` in the test plans of that use case's attacks (non-gap recommendations). This is the same set the attack tests send to. The `-out` combined configs are included, because their test-plan entries run the input rails; the output rails are only used by `test --with-output`.

Each benign request is sent to each of those configs with the same payload as the attack input test: `model`, one user message, and `guardrails.config_id`, with no `rail_types`. Benign and attack input numbers are therefore directly comparable. A call counts as blocked when the response has `status: blocked`.

Results go to `<run-dir>/benign_results.json`, one record per call, sorted by use case, config and request. The record has `use_case`, `request_id`, `kind`, `config_id`, `rails`, `status`, `blocked`, `blocking_rail` and `error`. The command prints blocked/total per config (plain and borderline split), and for each option rank how many options have a false-positive rate of 0, above 0, or at least 25% (on their input config). `test --summarize` adds a "Benign FP" column for each rail that has a single-rail benign config.

Calls that errored are **not** in the denominator: an error is neither a block nor a pass, so counting it as "not blocked" would make the false-positive rate look lower. Errors are reported separately per config and overall.

**Benign output test (replies).** The same benign requests can also be checked against the output rails, using replies the model gave to them. Pass a benign replies file keyed by request id (`examples/benign_requests/benign_replies.json`, same shape as `baseline_replies.json`). `--benign-replies` requires `--benign-requests`, because the user message comes from it. The shipped replies were generated with `scripts/generate_benign_replies.py --benign-dir examples/benign_requests --pipeline-results examples/pipeline_results --out <file>`, which calls the target model under the same conditions as the garak baseline (temperature 0, one artifact's system turn per request):

```bash
uv run asago-guardrails-recommender test --run-dir output/<run-id> --nemo-url http://localhost:8000 \
  --benign-requests examples/benign_requests --benign-replies examples/benign_requests/benign_replies.json
```

Configs: the output configs the output check uses for the use case, i.e. `config_name(option.config_id)` for each non-gap attack option that has output rails (the same selection as `test --with-output`). Each benign reply is sent to each of those configs with the same payload as the output check with `--baseline-replies`: user message = the benign request text, assistant message = the reply's `rendered` text, and `guardrails.rail_types: ["output"]`. A request with no reply for its use case is recorded as an error and not sent. Results go to `<run-dir>/benign_output_results.json`, with the same keys as `benign_results.json` plus `stage: "output"`. The summary and option-level distribution use the output configs; errors are excluded as above.

## Outputs

| Path | Contents |
|---|---|
| `output/<run-id>/attacks.json` | Attacks that were loaded |
| `output/<run-id>/signals.json` | Signals per attack, with their source (deterministic or LLM) and role (essential or incidental) |
| `output/<run-id>/candidates.json` | Ranked candidate rails per attack |
| `output/<run-id>/recommendations.json` | Status (`recommended`, `low_confidence` or `gap`) and options per attack |
| `output/<run-id>/report.md` | Readable summary, including gaps and the most common missing signals |
| `output/<run-id>/configs/` | One NeMo config per option |
| `output/<run-id>/server_configs/` | The same configs, deduplicated and named by `config_id`, ready to mount |
| `output/<run-id>/test_results.json` | Result of every test |
| `output/efficacy/records.jsonl` | One efficacy record per test, appended across runs |

To show your run in the demo:

```bash
uv run asago-guardrails-recommender snapshot --pipeline-results <my_results> --run-dir output/<run-id> --out demo/data
```

See [../demo/README.md](../demo/README.md) for the optional policy-mapper inputs.

## Configuration

| Variable or flag | Used by | Purpose |
|---|---|---|
| `LITELLM_BASE_URL` / `--llm-base-url` | recommend | OpenAI-compatible endpoint for the tagger and the LLM-judge rail |
| `LITELLM_API_KEY` or `OPENAI_API_KEY` | recommend | API key for that endpoint |
| `--tagger-model`, `--guard-model` | recommend | Models for tagging and for the LLM-judge rail (default `qwen-3.8-27b`) |
| `--no-thinking-kwargs` | recommend | Don't send the vLLM/Qwen thinking setting |
| `--tag-cache` | recommend | Tag cache directory (default `<out>/.tag_cache`) |
| `ASAGO_PIPELINE_RESULTS` / `--pipeline-results` | recommend | Pipeline results directory |
| `--no-llm` | recommend | Deterministic signals only |
| `--image`, `--namespace`, `--name`, `--key-secret` | deploy | Server image, namespace, deployment name (default `asago-rec`), LLM key secret (default `litellm-master-key`) |
| `NEMO_URL` / `--nemo-url` | test | NeMo server base URL |
| `--guard-model` | test | Model sent with test requests |
| `--records` | test | Efficacy records file to summarize |
| `--use-cases` | run_baseline_batch | Limit the baseline to some use cases |

Every command has `--help`.
