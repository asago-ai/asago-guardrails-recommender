#!/usr/bin/env python3
"""Extract the target model's baseline reply per artifact from garak reports into baseline_replies.json.

Output rails are tested on the reply that the baseline actually judged, instead of a fresh reply.
Most replies in agentic use cases are tool calls with no text, so each record keeps the text, the
tool calls, and `rendered`: the text the output rails see (reply text, then one line per tool call).

Usage:
  python scripts/extract_baseline_replies.py --baseline-dir <baseline dir> --out <results>/baseline_replies.json
  The baseline dir holds baseline_summary.json and <use_case>/artifacts_exhaustive/<id>/evaluation/*/garak.report.jsonl.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def render_reply(text: str, tool_calls: list[dict]) -> str:
    lines = [text.strip()] if text and text.strip() else []
    for call in tool_calls:
        lines.append(f"[tool call] {call['name']}({call['arguments']})")
    return "\n".join(lines)


def final_reply(report: Path) -> dict | None:
    """Reply of the last judged attempt (status 2) in a garak report."""
    final = None
    with open(report) as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("entry_type") == "attempt" and str(rec.get("status")) == "2":
                final = rec
    if not final or not final.get("outputs"):
        return None
    out = final["outputs"][0] or {}
    tool_calls = [
        {"name": tc.get("function", {}).get("name", ""), "arguments": tc.get("function", {}).get("arguments", "")}
        for tc in (out.get("notes") or {}).get("tool_calls") or []
    ]
    text = out.get("text") or ""
    return {"text": text, "tool_calls": tool_calls, "rendered": render_reply(text, tool_calls)}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--baseline-dir", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)

    summary = json.loads((args.baseline_dir / "baseline_summary.json").read_text())
    replies, missing = {}, 0
    for art in summary.get("artifacts", []):
        aid, uc = art["artifact_id"], art["use_case"]
        reports = sorted(
            (args.baseline_dir / uc / "artifacts_exhaustive" / aid / "evaluation").glob("*/garak.report.jsonl")
        )
        reply = final_reply(reports[0]) if reports else None
        if reply is None:
            missing += 1
            continue
        replies[aid] = {"use_case": uc, "outcome": art.get("outcome"), "target_model": art.get("target_model"), **reply}

    args.out.write_text(json.dumps(dict(sorted(replies.items())), indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {len(replies)} replies to {args.out} ({missing} artifacts without a judged reply)")


if __name__ == "__main__":
    main()
