#!/usr/bin/env python3
"""Generate the target model's replies to benign requests, under the same conditions as the garak baseline.

Each benign request is answered in the context of one artifact's system turn (round-robin over the
use case's artifacts, sorted by artifact id), with the baseline params (temperature 0, max_tokens 1024,
tool_choice "auto" when tools exist). Output has the same shape as baseline_replies.json, plus `kind`
and `context_artifact`. A failed request is recorded with `error` (type and HTTP status only) and not counted.

Usage:
  LITELLM_BASE_URL=... LITELLM_API_KEY=... python scripts/generate_benign_replies.py \
      --benign-dir examples/benign_requests --pipeline-results <pipeline_results_dir> \
      --out examples/benign_requests/benign_replies.json --model gemma-4-26b
  --base-url defaults to $LITELLM_BASE_URL (then $LITELLM_ENDPOINT); the key is read from
  $LITELLM_API_KEY (then $OPENAI_API_KEY). Neither value is printed or written.
  The pipeline results dir holds <use_case>/artifacts_exhaustive/scenario:v2:*/*.json.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from pathlib import Path

import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_baseline_replies import render_reply  # noqa: E402

BASELINE_PARAMS = {"temperature": 0, "max_tokens": 1024}
TIMEOUT_S = 120

JSON_TYPES = {
    "str": "string",
    "string": "string",
    "int": "integer",
    "integer": "integer",
    "float": "number",
    "number": "number",
    "bool": "boolean",
    "boolean": "boolean",
    "dict": "object",
    "object": "object",
    "list": "array",
    "array": "array",
}


# Copied from build_conversation() in
# ~/Documents/TrustyAI/asago-examples-pr35/asago-demo/asago_demo/evaluation.py (tool derivation section).
# Kept in sync by hand; the source repo is not imported.
def derive_tools(system_content: str, declared: list | None = None) -> list[dict]:
    """Tool schemas for a context. Declared tools win; otherwise parse `- name(params): description` lines."""
    if declared:
        return copy.deepcopy(declared)
    tools = []
    for name, params, description in re.findall(r"^\s*-\s*([\w]+)\(([^)]*)\):\s*(.*)$", system_content or "", re.M):
        parameters = []
        properties = {}
        for declaration in (p.strip() for p in params.split(",") if p.strip()):
            match = re.fullmatch(r"(\w+)(?:\s*:\s*(\w+))?", declaration)
            if not match or (match[2] and match[2] not in JSON_TYPES):
                raise ValueError(f"Provide an explicit tool schema for {name}")
            parameter, declared_type = match.groups()
            if parameter in properties:
                raise ValueError(f"Duplicate parameter in tool schema for {name}")
            parameters.append(parameter)
            properties[parameter] = (
                {"type": JSON_TYPES[declared_type]}
                if declared_type
                else {"type": "number"}
                if parameter == "amount"
                else {}
            )
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": {"type": "object", "properties": properties, "required": parameters},
                },
            }
        )
    return tools


def context_for(index: int, artifacts: list[dict]) -> dict:
    """Round-robin: benign request i (0-based, sorted by id) uses artifact i % n."""
    return artifacts[index % len(artifacts)]


def build_request(artifact: dict) -> dict:
    """Messages = the artifact's system turn only; the caller appends the benign user turn."""
    system = artifact["turns"][0]
    if system.get("role") != "system":
        raise ValueError("The first turn of the artifact is not the system turn")
    tools = derive_tools(system.get("content") or "", artifact.get("tools"))
    body = {"messages": [{"role": "system", "content": system.get("content") or ""}]}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    return body


def load_artifacts(results_dir: Path, use_case: str) -> list[dict]:
    """Artifacts of one use case sorted by artifact id (the scenario directory name).

    Each scenario directory also holds validation.json and garak reports; only the file with a `turns` key is kept.
    """
    artifacts = []
    for path in sorted(results_dir.glob(f"{use_case}/artifacts_exhaustive/scenario:v2:*/*.json")):
        data = json.loads(path.read_text())
        if "turns" in data:
            artifacts.append({"id": path.parent.name, **data})
    return sorted(artifacts, key=lambda a: a["id"])


def error_label(exc: Exception) -> str:
    """Type and HTTP status only; never the message, which can contain the URL."""
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    return f"{type(exc).__name__} (HTTP {status})" if status else type(exc).__name__


def call_model(base_url: str, api_key: str, model: str, body: dict, user_text: str) -> dict:
    payload = {
        "model": model,
        "messages": body["messages"] + [{"role": "user", "content": user_text}],
        **BASELINE_PARAMS,
    }
    if "tools" in body:
        payload["tools"] = body["tools"]
        payload["tool_choice"] = body["tool_choice"]
    response = requests.post(
        f"{base_url}/chat/completions",
        json=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        timeout=TIMEOUT_S,
    )
    response.raise_for_status()
    message = response.json()["choices"][0]["message"]
    text = message.get("content") or ""
    tool_calls = [
        {"name": tc["function"].get("name", ""), "arguments": tc["function"].get("arguments", "")}
        for tc in message.get("tool_calls") or []
    ]
    return {"text": text, "tool_calls": tool_calls, "rendered": render_reply(text, tool_calls)}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--benign-dir", required=True, type=Path)
    ap.add_argument("--pipeline-results", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--base-url", default=None, help="default: $LITELLM_BASE_URL, then $LITELLM_ENDPOINT")
    ap.add_argument("--model", default="gemma-4-26b")
    args = ap.parse_args(argv)

    base_url = args.base_url or os.environ.get("LITELLM_BASE_URL") or os.environ.get("LITELLM_ENDPOINT")
    api_key = os.environ.get("LITELLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not base_url or not api_key:
        raise SystemExit("Set --base-url (or LITELLM_BASE_URL) and LITELLM_API_KEY (or OPENAI_API_KEY)")
    base_url = base_url.rstrip("/")

    replies: dict[str, dict] = {}
    counts: dict[str, dict[str, int]] = {}
    for path in sorted(args.benign_dir.glob("*.yaml")):
        spec = yaml.safe_load(path.read_text())
        use_case = spec["use_case"]
        artifacts = load_artifacts(args.pipeline_results, use_case)
        if not artifacts:
            raise SystemExit(f"No artifacts found for {use_case}")
        requests_sorted = sorted(spec.get("requests", []), key=lambda r: r["id"])
        stats = counts.setdefault(use_case, {"replies": 0, "tool_only": 0, "text_only": 0, "both": 0, "errors": 0})
        for index, req in enumerate(requests_sorted):
            ctx = context_for(index, artifacts)
            record = {
                "use_case": use_case,
                "kind": req["kind"],
                "target_model": args.model,
                "context_artifact": ctx["id"],
            }
            try:
                body = build_request(ctx)
                reply = call_model(base_url, api_key, args.model, body, req["text"])
            except (requests.RequestException, KeyError, IndexError, ValueError, TypeError) as exc:
                record["error"] = error_label(exc)
                stats["errors"] += 1
            else:
                record.update(outcome="benign", **reply)
                stats["replies"] += 1
                has_text, has_tools = bool(reply["text"].strip()), bool(reply["tool_calls"])
                key = "both" if has_text and has_tools else "tool_only" if has_tools else "text_only"
                stats[key] += 1
            replies[req["id"]] = record

    args.out.write_text(json.dumps(dict(sorted(replies.items())), indent=2, ensure_ascii=False) + "\n")
    for use_case, s in counts.items():
        print(
            f"{use_case}: {s['replies']} replies (tool_only {s['tool_only']}, text_only {s['text_only']}, "
            f"both {s['both']}), {s['errors']} errors"
        )
    print(f"wrote {len(replies)} records to {args.out}")


if __name__ == "__main__":
    main()
