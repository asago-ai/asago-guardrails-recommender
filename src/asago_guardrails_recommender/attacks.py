"""Attack loader: Load garak artifacts, join with scenarios and baseline outcomes."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from .models import AttackRecord

# Directory names for artifacts and scenarios (supports both layouts)
# Listed in precedence order; first-occurrence-per-scenario_id logic preserves exhaustive layout
ARTIFACT_DIRS = ("artifacts_exhaustive", "artifacts")
SCENARIO_DIRS = ("scenarios_exhaustive", "scenarios")


def load_attacks(
    use_cases: list[str] | None = None, pipeline_results_path: str | Path | None = None
) -> list[AttackRecord]:
    """Load all attack records from garak artifacts, filtered by use case (optional)."""
    if pipeline_results_path is None:
        raise ValueError("pipeline_results_path must be provided")

    pipeline_results = Path(pipeline_results_path)

    baseline_path = pipeline_results / "baseline_summary.json"
    baseline_outcomes = _load_baseline_outcomes(baseline_path)

    attacks_by_scenario: dict[str, AttackRecord] = {}
    failed = 0
    garak_files = []
    for artifact_dir in ARTIFACT_DIRS:
        garak_files.extend(pipeline_results.glob(f"*/{artifact_dir}/**/*-garak.json"))

    for garak_file in garak_files:
        try:
            with open(garak_file) as f:
                garak = json.load(f)

            scenario_id = garak.get("scenario_id")
            if not scenario_id:
                continue

            # Skip non-exhaustive runs (keep only first occurrence per scenario_id)
            if scenario_id in attacks_by_scenario:
                continue

            # Determine use case from file path
            uc = garak_file.relative_to(pipeline_results).parts[0]

            # Filter by use cases if requested
            if use_cases and uc not in use_cases:
                continue

            # Build attack record
            attack = _parse_garak_to_attack(garak_file, garak, uc, baseline_outcomes.get(scenario_id))
            attacks_by_scenario[scenario_id] = attack
        except Exception as e:
            failed += 1
            print(f"Warning: Failed to parse {garak_file}: {e}")
            continue

    scenario_index = _build_scenario_index(pipeline_results)
    for attack in attacks_by_scenario.values():
        scenario_data = scenario_index.get(attack.attack_id)
        if scenario_data:
            attack.scenario_path = scenario_data["path"]
            attack.threat_id = scenario_data.get("threat_id")
            attack.mechanism = scenario_data.get("mechanism_name")
            attack.owasp_ids = scenario_data.get("owasp_ids", [])
            attack.atlas_ids = scenario_data.get("atlas_ids", [])
            attack.laaf_ids = scenario_data.get("laaf_ids", [])

    # Report stats
    join_hits = sum(1 for a in attacks_by_scenario.values() if a.scenario_path)
    baseline_hits = sum(1 for a in attacks_by_scenario.values() if a.baseline_outcome)
    print(f"Attacks: {len(attacks_by_scenario)}, scenario joins: {join_hits}, baseline joins: {baseline_hits}")
    if failed:
        print(f"Warning: {failed} garak file(s) failed to parse and were skipped")

    return list(attacks_by_scenario.values())


def _load_baseline_outcomes(baseline_path: Path) -> dict[str, str]:
    """Load scenario_id -> outcome from baseline_summary.json."""
    outcomes = {}
    if not baseline_path.exists():
        return outcomes

    with open(baseline_path) as f:
        data = json.load(f)

    for record in data.get("artifacts", []):
        scenario_id = record.get("artifact_id")
        outcome = record.get("outcome")
        if scenario_id and outcome:
            outcomes[scenario_id] = outcome

    return outcomes


def _parse_garak_to_attack(
    garak_file: Path, garak: dict[str, Any], use_case: str, baseline_outcome: str | None
) -> AttackRecord:
    """Convert a garak.json into an AttackRecord."""
    scenario_id = garak.get("scenario_id", "")
    attack_turn_index = garak.get("attack_turn_index", 0)
    turns = garak.get("turns", [])
    injection_surface = garak.get("injection_surface", "")
    narrative_summary = garak.get("narrative", {}).get("summary", "")

    # Extract adversarial text
    adversarial_text = ""
    if 0 <= attack_turn_index < len(turns):
        adversarial_text = turns[attack_turn_index].get("content", "")

    # Build messages list (drop tool-role and tool_calls; keep system/user/assistant with content)
    messages: list[dict[str, Any]] = []
    for i, turn in enumerate(turns[: attack_turn_index + 1]):
        role = turn.get("role", "")
        content = turn.get("content", "")

        if role in ("system", "user", "assistant") and isinstance(content, str) and content:
            messages.append({"role": role, "content": content})

    # Build short_id
    scenario_hash = hashlib.sha256(scenario_id.encode()).hexdigest()
    short_id = f"{use_case[:2]}-{scenario_hash[:8]}"

    return AttackRecord(
        attack_id=scenario_id,
        short_id=short_id,
        use_case=use_case,
        artifact_path=str(garak_file),
        scenario_path=None,
        adversarial_text=adversarial_text,
        messages=messages,
        attack_turn_index=attack_turn_index,
        injection_surface=injection_surface,
        narrative_summary=narrative_summary,
        baseline_outcome=baseline_outcome,
    )


def _build_scenario_index(pipeline_results: Path) -> dict[str, dict[str, Any]]:
    """Build scenario_id -> scenario_data index from all scenario YAML/JSON files."""
    index: dict[str, dict[str, Any]] = {}

    scenario_dirs = []
    for scenario_dir_name in SCENARIO_DIRS:
        scenario_dirs.extend(pipeline_results.glob(f"*/{scenario_dir_name}/*/scenarios"))

    for scenario_dir in scenario_dirs:
        if not scenario_dir.exists():
            continue

        # Parse all YAML files in the directory
        for scenario_file in scenario_dir.glob("scenario:v2:*.yaml"):
            try:
                with open(scenario_file) as f:
                    scenario = yaml.safe_load(f) or {}

                scenario_id = scenario.get("scenario_id")
                if not scenario_id:
                    continue

                # Extract seed metadata
                seed = scenario.get("scenario_seed_metadata", {})
                threat_id = seed.get("threat_id")
                mechanism_name = seed.get("attack_pattern_name")
                owasp_origin = seed.get("owasp_origin")
                atlas_ids = seed.get("atlas_technique_ids", [])
                laaf_ids = seed.get("laaf_technique_ids", [])

                owasp_ids = [owasp_origin] if owasp_origin else []

                index[scenario_id] = {
                    "path": str(scenario_file),
                    "threat_id": threat_id,
                    "mechanism_name": mechanism_name,
                    "owasp_ids": owasp_ids,
                    "atlas_ids": atlas_ids,
                    "laaf_ids": laaf_ids,
                }
            except Exception as e:
                print(f"Warning: Failed to parse {scenario_file}: {e}")
                continue

    return index


if __name__ == "__main__":
    import os

    pipeline_results_path = os.getenv("ASAGO_PIPELINE_RESULTS")
    if not pipeline_results_path:
        raise ValueError("ASAGO_PIPELINE_RESULTS env var not set")

    attacks = load_attacks(pipeline_results_path=pipeline_results_path)

    by_uc = defaultdict(int)
    for attack in attacks:
        by_uc[attack.use_case] += 1

    print(f"Total attacks: {len(attacks)}")
    for uc in sorted(by_uc.keys()):
        print(f"  {uc}: {by_uc[uc]}")

    join_hits = sum(1 for a in attacks if a.scenario_path)
    join_misses = len(attacks) - join_hits
    print(f"\nScenario join: {join_hits} hits, {join_misses} misses")

    baseline_hits = sum(1 for a in attacks if a.baseline_outcome)
    baseline_misses = len(attacks) - baseline_hits
    print(f"Baseline join: {baseline_hits} hits, {baseline_misses} misses")
