#!/usr/bin/env python3
"""Generate guardrail-catalog/INDEX.md from the rail catalog."""

import argparse
from pathlib import Path

from .catalog import load_catalog
from .models import CATALOG_DIR, REPO_ROOT

LLM_TIER = 2


def build_index() -> str:
    cards = sorted(load_catalog(include_extended=True), key=lambda c: (c.tier, c.type, c.id))
    lines = [
        "<!-- Generated file. Regenerate with: asago-guardrails-recommender catalog-index -->",
        "",
        "# Rail Index",
        "",
        "Generated from `guardrail-catalog/rails`. Regenerate with `asago-guardrails-recommender catalog-index`.",
        "",
        "| Rail id | Mechanism | Tier | Needs LLM | Detects signals | Placement |",
        "|---|---|---|---|---|---|",
    ]
    for c in cards:
        detects = ", ".join(c.detects) if c.detects else "-"
        needs_llm = "yes" if c.tier >= LLM_TIER else "no"
        lines.append(f"| `{c.id}` | {c.type} | {c.tier} | {needs_llm} | {detects} | {c.placement} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Regenerate guardrail-catalog/INDEX.md from the catalog")
    parser.add_argument(
        "--out",
        type=Path,
        default=CATALOG_DIR / "INDEX.md",
        help="Output file (default: guardrail-catalog/INDEX.md)",
    )
    args = parser.parse_args(argv)

    args.out.write_text(build_index())
    try:
        rel_path = args.out.relative_to(REPO_ROOT)
        print(f"Wrote {rel_path} ({len(load_catalog(include_extended=True))} rails)")
    except ValueError:
        # Output is not under REPO_ROOT
        print(f"Wrote {args.out} ({len(load_catalog(include_extended=True))} rails)")


if __name__ == "__main__":
    main()
