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
uv run asago-guardrails-recommender snapshot --pipeline-results <my_results> --use-cases-dir ../examples/use_cases --run-dir output/<run-id> --out ../demo/data
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
