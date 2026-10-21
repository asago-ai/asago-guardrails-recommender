# ASAGO Guardrails Recommender

Attack-specific NeMo Guardrails recommendations for the ASAGO pipeline: tags each attack with signals, selects a minimal set of rails from the guardrail catalog, builds NeMo configs, and tests them via /v1/checks.

## Commands

```bash
# Install / sync dependencies
uv sync --group dev

# Run all tests (includes an exact reproduction of examples/run1 from the tag cache)
uv run pytest tests/ -q

# Lint
uv run ruff check .

# CLI
uv run asago-guardrails-recommender recommend ...      # tag, select, build configs
uv run asago-guardrails-recommender deploy ...         # Kubernetes manifests
uv run asago-guardrails-recommender test ...           # /v1/checks tests or --summarize
uv run asago-guardrails-recommender catalog-index      # regenerate guardrail-catalog/INDEX.md
uv run asago-guardrails-recommender snapshot ...       # demo data

# Offline runs: no LLM endpoint needed
uv run asago-guardrails-recommender recommend --no-llm ...
uv run asago-guardrails-recommender recommend --tag-cache examples/tag_cache/qwen-3.8-27b ...
```

## Architecture

Pipeline: load attacks -> rail cards -> tag -> candidate pool -> select -> build NeMo configs -> deploy -> test via `/v1/checks`.

- `src/asago_guardrails_recommender/cli.py`: single CLI with subcommands recommend, deploy, test, catalog-index, snapshot. Each module exposes `main(argv=None)`.
- `attacks.py`: loads attacks from ASAGO pipeline results; use case = first path part under the results dir
- `catalog.py`: reads guardrail-catalog/rails into rail cards
- `tag.py`: deterministic signals plus one LLM call per attack, cached by attack id
- `recommend.py`: candidate pool (set intersection of signals), option selection, NeMo config build
- `deploy.py`: Kubernetes manifests (Deployment + Service per config)
- `test_rails.py`: /v1/checks tests and efficacy records
- `snapshot.py`: demo data; `catalog_index.py`: guardrail-catalog/INDEX.md
- Data: `guardrail-catalog/` (rails), `examples/` (run1 inputs, tag cache, reference results), `demo/` (static demo)
- Docs: README.md is the overview; step-by-step guides are in docs/asago-pipeline.md and docs/deploy-and-test.md; design rationale in docs/design.md.

## Key Conventions

- One main threat type per attack (`threat_id` from scenario seed metadata). It goes into the tagger prompt but not into scoring.
- Selection: at most 2 rails per option, at most 1 tier-2 (model-based) rail. Statuses are `recommended`, `low_confidence`, `gap`.
- `guardrail-catalog/INDEX.md` is generated. After editing rails, run `catalog-index`; never hand-edit the index.
- Outputs are sorted for determinism. `tests/test_smoke.py` checks that a cached run reproduces `examples/run1` exactly; if you change selection, ordering or config generation on purpose, regenerate `examples/run1` in the same change.
- Keep paths under `examples/` relative.
- LLM endpoint: any OpenAI-compatible endpoint. `chat_template_kwargs` to disable thinking is sent by default; turn it off with `--no-thinking-kwargs` for endpoints that reject it.
- `test` sends only the attack turn (`adversarial_text`) to /v1/checks. /v1/checks checks every message in the request separately, including the system prompt, so never send the whole conversation as the attack probe.

## NeMo Notes

- Config build applies fixes the raw catalog needs: flow names, `$classifier` parameters, a YARA input flow, and a Presidio `from_dict` patch in `actions.py`. Don't remove them without re-testing on a live server.
- `/v1/checks` doesn't forward request headers, so the NeMo server needs `OPENAI_API_KEY` set as an env var for LLM-judge rails.
- The server image must include `nemoguardrails.http`, presidio-analyzer and torch. The default image digest is in `deploy.py` (`DEFAULT_IMAGE`); the RHOAI 3.5.1 image doesn't work.
- The two HF classifier rails download their models at startup and need access to Hugging Face.
- A request counts as blocked when the response has `status == "blocked"`.

## Don'ts

- No secrets, API keys or cluster hostnames in code, examples or outputs. `snapshot` scrubs hosts and local paths; keep it that way.
- Don't commit `config.yaml`, `output/` or `.tag_cache/` (all gitignored).

## Development

- `AGENTS.md` is a symlink to `CLAUDE.md` — they are the same file.
- DO NOT skip updating `CLAUDE.md`/`AGENTS.md` and `README.md` when changes require it.
