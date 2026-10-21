"""Command-line entry point: asago-guardrails-recommender <command> [options]."""

import sys

COMMANDS = {
    "recommend": ("asago_guardrails_recommender.recommend", "Tag attacks, select rails, build NeMo configs"),
    "deploy": ("asago_guardrails_recommender.deploy", "Write Kubernetes manifests for the generated configs"),
    "test": ("asago_guardrails_recommender.test_rails", "Test configs against NeMo /v1/checks, or summarize efficacy"),
    "catalog-index": ("asago_guardrails_recommender.catalog_index", "Regenerate guardrail-catalog/INDEX.md"),
    "snapshot": ("asago_guardrails_recommender.snapshot", "Build the demo data snapshot"),
}


def _usage() -> str:
    lines = ["usage: asago-guardrails-recommender <command> [options]", "", "commands:"]
    lines += [f"  {name:<14} {desc}" for name, (_, desc) in COMMANDS.items()]
    lines += ["", "Run 'asago-guardrails-recommender <command> --help' for command options."]
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(_usage())
        sys.exit(0 if len(sys.argv) >= 2 else 1)
    name, argv = sys.argv[1], sys.argv[2:]
    if name not in COMMANDS:
        print(f"unknown command: {name}\n\n{_usage()}", file=sys.stderr)
        sys.exit(2)
    module = __import__(COMMANDS[name][0], fromlist=["main"])
    sys.argv[0] = f"asago-guardrails-recommender {name}"
    module.main(argv)
