#!/usr/bin/env python3
"""Build static JSON snapshot for ASAGO recommender HTML demo."""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .attacks import ARTIFACT_DIRS, SCENARIO_DIRS

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_DIR = REPO_ROOT / "demo"


def truncate_text(text: str, max_chars: int = 300) -> str:
    """Truncate text and add ellipsis if needed."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."


def discover_use_cases(pipeline_results: Path) -> List[str]:
    """Discover use cases from pipeline_results directory.

    Returns list of use-case IDs (immediate subdirectories containing artifacts_exhaustive or artifacts),
    sorted by name.
    """
    if not pipeline_results.exists():
        return []
    use_case_ids = []
    for uc_dir in sorted(pipeline_results.glob("*/")):
        for artifact_dir in ARTIFACT_DIRS:
            if (uc_dir / artifact_dir).exists():
                use_case_ids.append(uc_dir.name)
                break
    return use_case_ids


def derive_use_case_title(use_case_id: str) -> str:
    """Derive title from use case ID: strip NN_ prefix, replace underscores, title-case."""
    title = re.sub(r"^[0-9]+_", "", use_case_id)
    title = title.replace("_", " ")
    return title.title()


def artifact_turns(artifact_path: str):
    """Full conversation from garak artifact, including tool turns."""
    try:
        g = json.load(open(artifact_path))
    except Exception:
        return None, None
    turns = []
    for t in g.get("turns", []):
        item = {"role": t.get("role"), "content": truncate_text(str(t.get("content") or ""), 1500)}
        calls = [(c.get("function") or {}).get("name") for c in (t.get("tool_calls") or []) if isinstance(c, dict)]
        calls = [c for c in calls if c]
        if calls:
            item["tool_calls"] = calls
        if t.get("adversarial"):
            item["adversarial"] = True
        turns.append(item)
    return turns, g.get("attack_turn_index")


def truncate_turns(messages: List[Dict], max_chars: int = 1500) -> List[Dict]:
    """Truncate message content."""
    result = []
    for msg in messages:
        truncated = msg.copy()
        if "content" in truncated and isinstance(truncated["content"], str):
            truncated["content"] = truncate_text(truncated["content"], max_chars)
        result.append(truncated)
    return result


def load_use_cases(use_cases_dir: Path, use_case_ids: List[str]) -> Dict[str, Dict]:
    """Load use case definitions for the provided use-case IDs."""
    use_cases = {}
    for uc_id in use_case_ids:
        uc_dir = use_cases_dir / uc_id
        use_case_file = uc_dir / "use_case.txt"
        policy_link_file = uc_dir / "policy_link.txt"
        use_cases[uc_id] = {
            "id": uc_id,
            "description": use_case_file.read_text() if use_case_file.exists() else "",
            "policy_link": policy_link_file.read_text().strip() if policy_link_file.exists() else "",
        }
    return use_cases


CHAIN_FIELDS = ("threat", "threat_source", "vulnerability", "consequence", "impact")
THREAT_NAMES = {
    "T2": "Tool Misuse",
    "T3": "Privilege Compromise",
    "T5": "Cascading Hallucination Attacks",
    "T7": "Misaligned & Deceptive Behaviors",
    "T8": "Repudiation & Untraceability",
    "T9": "Identity Spoofing & Impersonation",
    "T10": "Overwhelming Human in the Loop",
    "T15": "Human Manipulation",
}


def load_policy_raw(uc_id: str, policy_paths: Dict[str, Path]) -> Optional[Dict]:
    """Load policy-mapper output (risk-extraction.json) for a use case."""
    if uc_id not in policy_paths:
        return None
    f = policy_paths[uc_id]
    if not f.exists():
        return None
    with open(f) as fh:
        return json.load(fh)


def load_policy(
    uc_id: str, policy_paths: Dict[str, Path], policy_names: Dict[str, str], policy_docs: Dict[str, str]
) -> Optional[Dict]:
    """Load policy-mapper output with evidence, causal chains, and mitigations."""
    policy = load_policy_raw(uc_id, policy_paths)
    if policy is None:
        return None

    all_risks = policy.get("risks", [])
    risks = []
    for risk in all_risks[:15]:
        evidence = [truncate_text(ev.get("text", ""), 300) for ev in risk.get("evidence", [])[:2]]
        item = {
            "id": risk.get("risk_id"),
            "name": risk.get("risk_name"),
            "taxonomy": risk.get("taxonomy"),
            "grounding_confidence": risk.get("grounding_confidence"),
            "evidence": evidence,
            "evidence_total": len(risk.get("evidence", [])),
        }
        for k in CHAIN_FIELDS:
            if risk.get(k):
                item[k] = truncate_text(str(risk[k]), 300)
        mits = []
        for m in (risk.get("mitigations") or [])[:3]:
            mits.append(
                {
                    "name": truncate_text(str(m.get("action_name") or m.get("action_id") or ""), 120),
                    "description": truncate_text(str(m.get("description") or ""), 300),
                    "source": m.get("source"),
                }
            )
        if mits:
            item["mitigations"] = mits
            item["mitigations_total"] = len(risk.get("mitigations") or [])
        risks.append(item)

    rs = policy.get("retrieval_stats", {})
    meta = policy.get("metadata", {})
    policy_link = ""

    return {
        "name": policy_names.get(uc_id, f"Policy for {uc_id}"),
        "link": policy_link,
        "risks": risks,
        "risks_total": len(all_risks),
        "stats": {
            "chunks": rs.get("total_chunks"),
            "candidates_retrieved": rs.get("total_candidates_retrieved"),
            "auto_accepted": rs.get("auto_accepted"),
            "llm_judged": rs.get("llm_judged"),
            "grounding_filtered": rs.get("grounding_filtered"),
            "with_causal_chain": sum(1 for r in all_risks if r.get("threat")),
            "model": meta.get("model"),
            "cross_encoder": meta.get("cross_encoder_model"),
            "bi_encoder": meta.get("bi_encoder_model"),
            "timestamp": meta.get("timestamp"),
        },
    }


def final_run_dir(uc_id: str, pipeline_results: Path) -> Optional[Path]:
    """The scenario-generator run that produced admitted scenarios (has finalization-inventory.json)."""
    for scenario_dir_name in SCENARIO_DIRS:
        scenarios_dir = pipeline_results / uc_id / scenario_dir_name
        if not scenarios_dir.exists():
            continue
        for d in sorted(scenarios_dir.glob("*/")):
            if (d / "finalization-inventory.json").exists():
                return d
    return None


def _threat_sort_key(tid: str):
    m = re.match(r"T(\d+)$", tid)
    return int(m.group(1)) if m else 999


def load_battery(uc_id: str, pipeline_results: Path) -> Dict:
    """Threat surface from scenario-generator run: risks -> threats -> attack patterns."""
    run = final_run_dir(uc_id, pipeline_results)
    f = run / "threat-surface.yaml" if run else None
    if not f or not f.exists():
        return {"derived": True, "threats": []}
    try:
        with open(f) as fh:
            data = yaml.safe_load(fh)
        entries = data.get("entries", [])
        all_patterns = sorted({ap for e in entries for ap in e.get("attack_pattern_ids", [])})
        threats = {}
        for e in entries:
            for tid in e.get("agentic_threat_ids", []):
                t = threats.setdefault(tid, {"risks": set()})
                t["risks"].add(e.get("risk_card", {}).get("risk_id"))
        out = []
        for tid in sorted(threats, key=_threat_sort_key):
            out.append(
                {
                    "threat_id": tid,
                    "threat_name": THREAT_NAMES.get(tid, tid),
                    "attack_patterns": [p for p in all_patterns if p.startswith(f"AP-{tid}-")],
                    "risks_mapped": len(threats[tid]["risks"]),
                }
            )
        return {
            "source_file": str(f),
            "derived": False,
            "risk_cards": len(entries),
            "governance_only": len(data.get("governance_only", [])),
            "attack_patterns_total": len(all_patterns),
            "threats": out,
        }
    except Exception as e:
        print(f"Warning: Failed to load battery from {f}: {e}", file=sys.stderr)
        return {"derived": True, "threats": []}


def load_scenarios(uc_id: str, pipeline_results: Path) -> Dict[str, Dict]:
    """Load all scenarios for a use case."""
    run = final_run_dir(uc_id, pipeline_results)
    scenarios_dir = None
    if run:
        scenarios_dir = run
    else:
        for scenario_dir_name in SCENARIO_DIRS:
            candidate = pipeline_results / uc_id / scenario_dir_name
            if candidate.exists():
                scenarios_dir = candidate
                break

    scenarios = {}
    if not scenarios_dir or not scenarios_dir.exists():
        return scenarios

    for scenario_file in scenarios_dir.glob("**/scenario:v2:*.yaml"):
        try:
            with open(scenario_file) as f:
                data = yaml.safe_load(f)

            scenario_id = data.get("scenario_id")
            if scenario_id:
                seed_meta = data.get("scenario_seed_metadata", {})
                narrative = data.get("narrative", {})
                narrative_summary = narrative.get("summary", "")
                if narrative_summary:
                    narrative_summary = truncate_text(narrative_summary, 500)

                steps = []
                narrative_steps = narrative.get("steps", [])
                if narrative_steps and isinstance(narrative_steps, list):
                    for step_item in narrative_steps[:6]:
                        if isinstance(step_item, dict):
                            action = step_item.get("action", "")
                            if action:
                                steps.append(truncate_text(str(action), 200))
                        elif isinstance(step_item, str):
                            if step_item.strip():
                                steps.append(truncate_text(step_item.strip(), 200))

                entry_point = narrative.get("entry_point", "")
                actor_profile = data.get("actor_profile", {})
                actor_type = actor_profile.get("actor_type", "")

                scenarios[scenario_id] = {
                    "scenario_id": scenario_id,
                    "threat_id": seed_meta.get("threat_id"),
                    "threat_name": seed_meta.get("threat_name"),
                    "attack_pattern_name": seed_meta.get("attack_pattern_name"),
                    "narrative_summary": narrative_summary,
                    "steps": steps,
                    "entry_point": entry_point,
                    "actor_type": actor_type,
                }
        except Exception as e:
            print(f"Warning: Failed to load scenario {scenario_file}: {e}", file=sys.stderr)

    return scenarios


def load_attacks(run_dir: Path) -> List[Dict]:
    """Load attacks from attacks.json."""
    attacks_file = run_dir / "attacks.json"
    if not attacks_file.exists():
        return []
    with open(attacks_file) as f:
        return json.load(f)


def load_signals(run_dir: Path) -> Dict[str, List]:
    """Load signals keyed by attack_id."""
    signals_file = run_dir / "signals.json"
    if not signals_file.exists():
        return {}
    with open(signals_file) as f:
        return json.load(f)


def load_candidates(run_dir: Path) -> Dict[str, List]:
    """Load candidates keyed by attack_id."""
    candidates_file = run_dir / "candidates.json"
    if not candidates_file.exists():
        return {}
    with open(candidates_file) as f:
        return json.load(f)


def load_recommendations(run_dir: Path) -> Dict[str, Dict]:
    """Load recommendations keyed by attack_id."""
    recommendations_file = run_dir / "recommendations.json"
    if not recommendations_file.exists():
        return {}
    with open(recommendations_file) as f:
        recs_list = json.load(f)
    return {rec["attack_id"]: rec for rec in recs_list}


def load_test_results(run_dir: Path) -> List[Dict]:
    """Load test results."""
    test_results_file = run_dir / "test_results.json"
    if not test_results_file.exists():
        return []
    with open(test_results_file) as f:
        return json.load(f)


def redact_api_keys(text: str) -> str:
    """Redact API keys and secrets from config text."""
    patterns = [
        (r'api[_-]?key\s*[:=]\s*["\']?[^\s"\']+', "api_key: [REDACTED]"),
        (r'api[_-]?secret\s*[:=]\s*["\']?[^\s"\']+', "api_secret: [REDACTED]"),
        (r'token\s*[:=]\s*["\']?[^\s"\']+', "token: [REDACTED]"),
        (r'password\s*[:=]\s*["\']?[^\s"\']+', "password: [REDACTED]"),
        (r"bearer\s+[^\s]+", "bearer [REDACTED]"),
        (r'key\s*[:=]\s*["\']?[A-Za-z0-9]{32,}["\']?', "key: [REDACTED]"),
    ]
    result = text
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


def scrub_environment(snapshot: Dict) -> Dict:
    """Remove cluster hostnames and local filesystem paths from the snapshot."""
    text = json.dumps(snapshot)
    text = re.sub(r'https?://[^\s"\']*openshiftapps\.com', "https://<redacted-host>", text)
    text = re.sub(r'(?:/Users|/home)/[^"\s]*?/(?=pipeline_results/|output/)', "", text)
    text = re.sub(r'(?:/Users|/home)/[^/"\s]+', "~", text)
    return json.loads(text)


def load_detector_rubric(artifact_path: str) -> Optional[Dict]:
    """Load detector_rubric from garak.json artifact file."""
    if not artifact_path:
        return None
    path = Path(artifact_path)
    if not path.exists():
        return None
    try:
        with open(path) as f:
            data = json.load(f)
        rubric = data.get("detector_rubric")
        if rubric:
            if isinstance(rubric, dict) and "judge_prompt" in rubric:
                rubric = rubric.copy()
                rubric["judge_prompt"] = truncate_text(rubric["judge_prompt"], 600)
            return rubric
        return None
    except Exception as e:
        print(f"Warning: Failed to load rubric from {artifact_path}: {e}", file=sys.stderr)
        return None


def load_nemo_config(config_dir: str) -> Optional[Dict]:
    """Load NeMo config files (config.yml and rails.co) from a config directory."""
    if not config_dir:
        return None
    config_path = Path(config_dir)
    if not config_path.exists():
        return None

    config_yml = ""
    rails_co = ""

    yml_file = config_path / "config.yml"
    if yml_file.exists():
        try:
            content = yml_file.read_text()
            config_yml = redact_api_keys(truncate_text(content, 6000))
        except Exception as e:
            print(f"Warning: Failed to load config.yml from {config_dir}: {e}", file=sys.stderr)

    rails_file = config_path / "rails.co"
    if rails_file.exists():
        try:
            content = rails_file.read_text()
            rails_co = redact_api_keys(truncate_text(content, 6000))
        except Exception as e:
            print(f"Warning: Failed to load rails.co from {config_dir}: {e}", file=sys.stderr)

    if config_yml or rails_co:
        return {
            "config_yml": config_yml,
            "rails_co": rails_co,
        }
    return None


def load_rail_catalog(catalog_dir: Path) -> Dict[str, Dict]:
    """Load rail catalog from YAML files."""
    rails = {}
    if not catalog_dir.exists():
        return rails

    for yaml_file in sorted(catalog_dir.glob("*.yaml")):
        rail_id = yaml_file.stem
        try:
            with open(yaml_file) as f:
                _rail_data = yaml.safe_load(f)

            description = ""
            rail_type = "unknown"
            requires_llm = False

            if rail_id.startswith("pii_"):
                rail_type = "pii"
                entity = rail_id[4:]
                description = f"Detect personally identifiable information: {entity}"
            elif "classifier" in rail_id:
                rail_type = "classifier"
                description = f"Hugging Face classifier for {rail_id.replace('hf_classifier_', '')}"
            elif "injection_detector" in rail_id:
                rail_type = "injection"
                description = f"Detect {rail_id.replace('injection_detector_', '')} injection"
            elif "self_check" in rail_id:
                rail_type = "llm_judge"
                requires_llm = True
                description = "LLM-based policy compliance checker"

            config_name = compute_config_name(rail_id)

            rails[rail_id] = {
                "id": rail_id,
                "name": config_name,
                "description": description,
                "type": rail_type,
                "requires_llm": requires_llm,
            }
        except Exception as e:
            print(f"Warning: Failed to load rail {yaml_file}: {e}", file=sys.stderr)

    rails.setdefault(
        "self_check_input_policy",
        {
            "id": "self_check_input_policy",
            "name": compute_config_name("self_check_input_policy"),
            "description": "LLM-based policy compliance checker",
            "type": "llm_judge",
            "requires_llm": True,
        },
    )
    return rails


def compute_config_name(rail_id: str) -> str:
    """Compute config_name from rail_id."""
    explicit = {
        "hf_classifier_prompt-injection": "prompt-injection-detector",
        "hf_classifier_guardian-hap": "hate-speech-detector",
        "injection_detector_code": "code-injection-detector",
        "injection_detector_sqli": "sql-injection-detector",
        "injection_detector_xss": "xss-detector",
        "injection_detector_template": "template-injection-detector",
        "self_check_input_policy": "llm-policy-judge",
    }

    if rail_id in explicit:
        return explicit[rail_id]

    if rail_id.startswith("pii_"):
        entity = rail_id[4:]
        if entity == "PERSON":
            return "pii-name-detector"
        return f"pii-{entity.lower().replace('_', '-')}-detector"

    return rail_id.lower().replace("_", "-")


GATE_NAMES = [
    "identity",
    "resource_binding_validity",
    "execution_requirement_drift",
    "catalog_taxonomy_pin_validity",
    "projection_traceability",
    "identifier_validity",
    "structural_validity",
    "phantom_validity",
    "tool_integration_grounding",
    "data_access_grounding",
    "capability_grounding",
    "semantic_validity",
    "actor_attack_complexity",
    "behavior_correspondence",
    "narrative_tree_diagnostics",
    "tree_parsimony",
    "or_tree_prohibition",
]


def load_scenario_funnel(uc_id: str, pipeline_results: Path) -> Dict:
    """Scenario-generator evidence: finalization-inventory.json admission decisions."""
    run = final_run_dir(uc_id, pipeline_results)
    if not run:
        return {}
    fi_path = run / "finalization-inventory.json"
    if not fi_path.exists():
        return {}

    fi = json.load(open(fi_path))
    decisions = fi.get("admission_decisions", [])
    status = {}
    codes = {}
    for d in decisions:
        status[d.get("status")] = status.get(d.get("status"), 0) + 1
        if not d.get("admitted"):
            v = (d.get("violations") or [{}])[0]
            code = v.get("code") if isinstance(v, dict) else str(v)
            codes[code or "unspecified"] = codes.get(code or "unspecified", 0) + 1
    admitted = sum(1 for d in decisions if d.get("admitted"))
    gate_failures = {}
    for d in decisions:
        for g in d.get("gate_results", []):
            if g.get("applicable") and not g.get("passed"):
                gate_failures[g["gate"]] = gate_failures.get(g["gate"], 0) + 1

    cov = {}
    gaps = {}
    try:
        cov = json.load(open(run / "planning-checkpoint.json"))
        gaps = json.load(open(run / "coverage-gaps.json")).get("coverage_gaps", {})
    except Exception:
        pass

    log = (run / "pipeline.log").read_text() if (run / "pipeline.log").exists() else ""
    m = re.search(r"Rule pre-filter: (\d+)/(\d+) candidates rejected, (\d+) passed", log)
    ep = re.search(r"Entry point filter: (\d+)/(\d+) entry points", log)
    skipped_seeds = re.findall(r"Seed (AP-[A-Z0-9-]+) has no technique IDs", log)

    return {
        "run_dir": str(run),
        "enumerated": len(decisions),
        "admitted": admitted,
        "quarantined": len(decisions) - admitted,
        "rejected": status.get("rejected", 0),
        "generation_failed": status.get("generation_or_finalization_failed", 0),
        "quarantine_reasons": [{"code": k, "count": v} for k, v in sorted(codes.items(), key=lambda x: -x[1])],
        "gates": GATE_NAMES,
        "gate_failures": [{"gate": k, "count": v} for k, v in sorted(gate_failures.items(), key=lambda x: -x[1])],
        "candidates_attempted": len(cov.get("attempted_candidate_ids") or []),
        "rule_prefilter": (
            {"rejected": int(m.group(1)), "candidates": int(m.group(2)), "to_llm": int(m.group(3))} if m else None
        ),
        "entry_points": ({"accessible": int(ep.group(1)), "total": int(ep.group(2))} if ep else None),
        "seeds_without_techniques": skipped_seeds,
        "uncovered_attack_patterns": gaps.get("uncovered_attack_patterns", []),
    }


def load_artifact_funnel(uc_id: str, pipeline_results: Path, scenarios: Dict) -> Dict:
    """Artifact-generator evidence: artifacts_exhaustive/manifest.json or artifacts/manifest.json + validation."""
    artifacts_path = None
    for artifact_dir in ARTIFACT_DIRS:
        candidate = pipeline_results / uc_id / artifact_dir
        if candidate.exists():
            artifacts_path = candidate
            break

    if not artifacts_path:
        return {
            "per_scenario": {},
            "attempted": 0,
            "validated": 0,
            "produced": 0,
            "coverage_gate": {},
            "per_threat": [],
        }

    manifest_path = artifacts_path / "manifest.json"
    if not manifest_path.exists():
        return {
            "per_scenario": {},
            "attempted": 0,
            "validated": 0,
            "produced": 0,
            "coverage_gate": {},
            "per_threat": [],
        }

    manifest = json.load(open(manifest_path))
    per = {}
    scores_total = []
    for m in manifest:
        sid = m["scenario_id"]
        vf = artifacts_path / sid / "validation.json"
        val = json.load(open(vf)) if vf.exists() else {}
        art = Path(m.get("artifact_path", ""))
        per[sid] = {
            "ok": bool(m.get("ok")),
            "coverage_gate": m.get("gate_result"),
            "coverage_reason": m.get("gate_reason"),
            "validated": bool(val.get("ok")),
            "fidelity_total": val.get("fidelity_total"),
            "scores": val.get("scores"),
            "attempts": val.get("attempts"),
            "produced": art.exists(),
        }
        if val.get("fidelity_total") is not None:
            scores_total.append(val["fidelity_total"])

    by_threat = {}
    for sid, s in scenarios.items():
        t = by_threat.setdefault(s.get("threat_id"), {"admitted": 0, "artifacts": 0})
        t["admitted"] += 1
        if sid in per:
            t["artifacts"] += 1

    gates = {}
    for p in per.values():
        gates[p["coverage_gate"]] = gates.get(p["coverage_gate"], 0) + 1

    return {
        "per_scenario": per,
        "attempted": len(manifest),
        "validated": sum(1 for p in per.values() if p["validated"]),
        "produced": sum(1 for p in per.values() if p["produced"]),
        "coverage_gate": gates,
        "fidelity_min": min(scores_total) if scores_total else None,
        "fidelity_avg": round(sum(scores_total) / len(scores_total), 1) if scores_total else None,
        "per_threat": [
            {"threat_id": k, "name": THREAT_NAMES.get(k, k), **v}
            for k, v in sorted(by_threat.items(), key=lambda x: _threat_sort_key(x[0]))
        ],
    }


def _build_provenance(
    uc_id: str,
    battery: Dict,
    scenarios: Dict,
    attacks: List[Dict],
    policy: Optional[Dict],
    sf: Dict,
    af: Dict,
    tests_n: int,
    blocked_n: int,
    options_n: int,
    policy_doc: str = "",
) -> Dict:
    """Provenance per pipeline stage, built from run artifacts."""
    ps = (policy or {}).get("stats", {})
    outcomes = {}
    for a in attacks:
        o = a.get("baseline_outcome") or "unknown"
        outcomes[o] = outcomes.get(o, 0) + 1

    admitted_n = sf.get("admitted", len(scenarios))
    threat_ids = {a.get("threat_id") for a in attacks} if attacks else set()
    filtered = {sid: s for sid, s in scenarios.items() if s.get("threat_id") in threat_ids} if threat_ids else scenarios
    selected_n = len(filtered)
    attempted = af.get("attempted", 0)
    no_record = max(0, selected_n - attempted)

    threat_types = ", ".join(sorted(t for t in threat_ids if t)) or "none"
    rule = (
        f"All {admitted_n} admitted scenarios passed the scenario "
        f"generator's admission gates. {selected_n} of them belong to the "
        f"threat types that were turned into attacks ({threat_types}), and "
        f"{attempted} produced an artifact."
    )
    if no_record > 0:
        rule += f" {no_record} selected scenarios lack artifact records."

    return {
        "stages": {
            "policy": {
                "status": "ran",
                "source_doc": policy_doc,
                "model": ps.get("model"),
                "timestamp": ps.get("timestamp"),
                "outputs": {
                    "risks": (policy or {}).get("risks_total", 0),
                    "shown": len((policy or {}).get("risks", [])),
                },
                "stats": ps,
                "notes": (
                    "Output is risk-extraction.json / report.html only: "
                    "risks with evidence, causal chains and mitigations."
                ),
            },
            "battery": {
                "derived_from": "policy",
                "outputs": {
                    "threats": len(battery.get("threats", [])),
                    "attack_patterns": battery.get("attack_patterns_total", 0),
                },
                "source_file": battery.get("source_file"),
                "notes": (
                    "Built by the scenario generator (risk cards -> threats "
                    "via SSSOM -> threat-surface.yaml), not by the policy mapper."
                ),
            },
            "scenarios": {
                "model": "gemma-4-26b",
                "outputs": {
                    "generated": sf.get("enumerated", 0),
                    "admitted": admitted_n,
                    "quarantined": sf.get("quarantined", 0),
                },
                "generated": sf.get("enumerated", 0),
                "admitted": admitted_n,
                "quarantined": sf.get("quarantined", 0),
                "detail": sf,
                "per_threat": [
                    {"threat_id": t["threat_id"], "name": t["name"], "admitted": t["admitted"]}
                    for t in af.get("per_threat", [])
                ],
                "notes": (
                    "Generated = candidate scenarios enumerated and attempted; "
                    "admitted = passed all admission gates; quarantined = rejected "
                    "or failed generation (kept under quarantine/)."
                ),
            },
            "artifacts": {
                "model": "asago-artifact-generator (gemma-4-26b)",
                "outputs": {
                    "attempted": attempted,
                    "validated": af.get("validated", 0),
                    "produced": af.get("produced", 0),
                },
                "attempted": attempted,
                "validated": af.get("validated", 0),
                "produced": af.get("produced", 0),
                "admitted_input": admitted_n,
                "selected_n": selected_n,
                "no_record": max(no_record, 0),
                "coverage_gate": af.get("coverage_gate"),
                "fidelity_min": af.get("fidelity_min"),
                "fidelity_avg": af.get("fidelity_avg"),
                "per_threat": af.get("per_threat", []),
                "selection_rule": rule,
                "baseline": {
                    "script": "pipeline_automation/run_baseline_test.py (batch driver: run_baseline_batch.py)",
                    "target": "gemma-4-26b, no guardrails",
                    "outcomes": outcomes,
                },
            },
            "recommender": {
                "tagger_model": "qwen-3.8-27b",
                "outputs": {
                    "attacks": len(attacks),
                    "tagged": sum(1 for a in attacks if a.get("signals")),
                    "options": options_n,
                },
                "notes": f"Tagger+recommender for {len(attacks)} attacks from this use case (qwen-3.8-27b)",
            },
            "test": {
                "endpoint": "NeMo /v1/checks",
                "guard_model": "qwen-3.8-27b",
                "outputs": {"tests": tests_n, "blocked_attacks": blocked_n},
                "notes": (
                    f"NeMo /v1/checks evaluation: {blocked_n} of "
                    f"{len(attacks)} attacks blocked by guardrails ({tests_n} tests)"
                ),
            },
        }
    }


def build_snapshot(
    pipeline_results: Path,
    use_cases_dir: Path,
    run_dir: Path,
    catalog_dir: Path,
    policy_paths: Dict[str, Path],
    policy_names: Dict[str, str],
    policy_docs: Dict[str, str],
) -> Dict:
    """Build the complete snapshot."""
    print("Discovering use cases...", file=sys.stderr)
    use_case_ids = discover_use_cases(pipeline_results)
    if not use_case_ids:
        raise ValueError(
            f"No use cases found in {pipeline_results} (expected subdirectories with artifacts_exhaustive or artifacts)"
        )

    print("Loading use cases...", file=sys.stderr)
    use_cases_data = load_use_cases(use_cases_dir, use_case_ids)

    print("Loading battery and scenarios...", file=sys.stderr)
    batteries_by_uc = {uc: load_battery(uc, pipeline_results) for uc in use_cases_data.keys()}
    scenarios_by_uc = {uc: load_scenarios(uc, pipeline_results) for uc in use_cases_data.keys()}

    print("Loading attacks and related data...", file=sys.stderr)
    attacks = load_attacks(run_dir)
    signals_data = load_signals(run_dir)
    candidates_data = load_candidates(run_dir)
    recommendations_data = load_recommendations(run_dir)
    test_results = load_test_results(run_dir)

    print("Loading rail catalog...", file=sys.stderr)
    rails = load_rail_catalog(catalog_dir)

    use_cases_output = []
    attack_counts = {}
    blocked_counts = {}
    gap_counts = {}

    for uc_id in use_case_ids:
        uc_data = use_cases_data.get(uc_id, {})
        policy = load_policy(uc_id, policy_paths, policy_names, policy_docs)
        battery = batteries_by_uc[uc_id]
        scenarios = scenarios_by_uc[uc_id]

        af = load_artifact_funnel(uc_id, pipeline_results, scenarios)

        uc_attacks = [a for a in attacks if a["use_case"] == uc_id]
        attack_counts[uc_id] = len(uc_attacks)
        blocked_counts[uc_id] = 0
        gap_counts[uc_id] = 0

        scenario_list = []
        for scenario_id, scenario_data in scenarios.items():
            attack_for_scenario = next((a for a in uc_attacks if a["attack_id"] == scenario_id), None)

            scenario_list.append(
                {
                    "scenario_id": scenario_id,
                    "threat_id": scenario_data["threat_id"],
                    "threat_name": scenario_data["threat_name"],
                    "attack_pattern_name": scenario_data["attack_pattern_name"],
                    "narrative_summary": scenario_data["narrative_summary"],
                    "steps": scenario_data["steps"],
                    "entry_point": scenario_data["entry_point"],
                    "actor_type": scenario_data["actor_type"],
                    "attack_id": attack_for_scenario["attack_id"] if attack_for_scenario else None,
                }
            )

        uc_attacks_output = []
        for attack in uc_attacks:
            attack_id = attack["attack_id"]
            scenario_id = attack_id
            scenario = scenarios.get(scenario_id, {})
            signals = signals_data.get(attack_id, [])
            candidates = candidates_data.get(attack_id, [])
            rec = recommendations_data.get(attack_id, {})

            rec_output = None
            if rec:
                options = []
                for opt in rec.get("options", []):
                    config_dir = opt.get("config_dir", "")
                    if config_dir and not Path(config_dir).is_absolute():
                        config_dir = str(run_dir / config_dir)
                    nemo_config = load_nemo_config(config_dir)

                    opt_copy = {
                        "rank": opt.get("rank"),
                        "rails": opt.get("rails", []),
                        "config_name": ",".join([compute_config_name(r) for r in opt.get("rails", [])]),
                        "evidence": truncate_text(opt.get("evidence", ""), 300),
                        "cost_tier": opt.get("cost_tier"),
                        "covers_signals": opt.get("covers_signals", []),
                        "rationale": truncate_text(opt.get("rationale", ""), 300),
                    }
                    if nemo_config:
                        opt_copy["nemo_config"] = nemo_config

                    options.append(opt_copy)

                rec_output = {
                    "status": rec.get("status"),
                    "options": options,
                    "missing_signals": rec.get("missing_signals", []),
                }

                if rec.get("status") == "gap":
                    gap_counts[uc_id] += 1

            artifact_path = attack.get("artifact_path", "")
            detector_rubric = load_detector_rubric(artifact_path)
            tests = [t for t in test_results if t["attack_id"] == attack_id]

            for test in tests:
                if test.get("status") == "blocked":
                    blocked_counts[uc_id] += 1
                    break

            art_turns, art_idx = artifact_turns(artifact_path)
            attack_output = {
                "attack_id": attack_id,
                "short_id": attack.get("short_id"),
                "scenario_id": scenario_id,
                "threat_id": attack.get("threat_id"),
                "threat_name": scenario.get("threat_name"),
                "attack_pattern_name": scenario.get("attack_pattern_name"),
                "injection_surface": attack.get("injection_surface"),
                "narrative_summary": truncate_text(attack.get("narrative_summary", ""), 500),
                "adversarial_text": truncate_text(attack.get("adversarial_text", ""), 500),
                "turns": art_turns if art_turns else truncate_turns(attack.get("messages", [])),
                "attack_turn_index": art_idx if art_turns else attack.get("attack_turn_index"),
                "artifact": af["per_scenario"].get(scenario_id),
                "baseline_outcome": attack.get("baseline_outcome"),
                "signals": signals,
                "candidates": candidates,
                "recommendation": rec_output,
                "tests": [
                    {
                        "option_rank": t.get("option_rank"),
                        "test_label": t.get("test_label"),
                        "rails": t.get("rails", []),
                        "status": t.get("status"),
                        "blocking_rail": t.get("blocking_rail"),
                        "latency_ms": t.get("latency_ms"),
                    }
                    for t in tests
                ],
            }

            if detector_rubric:
                attack_output["detector_rubric"] = detector_rubric

            uc_attacks_output.append(attack_output)

        title_map = {
            "01_healthcare_us": "HealthHub Patient Portal Assistant",
            "02_banking_eu": "EuroBank Customer Service",
        }

        sf = load_scenario_funnel(uc_id, pipeline_results)
        provenance = _build_provenance(
            uc_id,
            battery,
            scenarios,
            uc_attacks_output,
            policy,
            sf,
            af,
            tests_n=sum(len(a["tests"]) for a in uc_attacks_output),
            blocked_n=blocked_counts.get(uc_id, 0),
            options_n=sum(len((a["recommendation"] or {}).get("options", [])) for a in uc_attacks_output),
            policy_doc=policy_docs.get(uc_id, ""),
        )

        use_cases_output.append(
            {
                "id": uc_id,
                "title": title_map.get(uc_id, derive_use_case_title(uc_id)),
                "description": truncate_text(uc_data.get("description", ""), 800),
                "policy": policy,
                "battery": battery,
                "scenarios": scenario_list,
                "attacks": uc_attacks_output,
                "provenance": provenance,
            }
        )

    total_attacks = sum(attack_counts.values())
    total_blocked = sum(blocked_counts.values())
    total_gaps = sum(gap_counts.values())

    summary = {
        "total_attacks": total_attacks,
        "total_blocked": total_blocked,
        "total_gaps": total_gaps,
        "per_use_case": {
            uc_id: {
                "attacks": attack_counts.get(uc_id, 0),
                "blocked": blocked_counts.get(uc_id, 0),
                "gaps": gap_counts.get(uc_id, 0),
            }
            for uc_id in use_case_ids
        },
        "test_results_total": len(test_results),
    }

    snapshot = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "run_id": "run1",
        "catalog": {
            "rails": list(rails.values()),
        },
        "use_cases": use_cases_output,
        "summary": summary,
    }

    return snapshot


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Build static JSON snapshot for ASAGO recommender HTML demo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 build_snapshot.py
  python3 build_snapshot.py --pipeline-results /path/to/pipeline_results \\
    --run-dir /path/to/run1
  python3 build_snapshot.py \\
    --policy 01_healthcare_us=/path/to/risk-extraction.json \\
    --policy 02_banking_eu=/path/to/risk-extraction.json
        """,
    )
    parser.add_argument(
        "--pipeline-results",
        type=Path,
        default=REPO_ROOT / "examples/pipeline_results",
        help="Path to pipeline_results directory (default: examples/pipeline_results)",
    )
    parser.add_argument(
        "--use-cases-dir",
        type=Path,
        default=REPO_ROOT / "examples/use_cases",
        help="Path to use cases directory (default: examples/use_cases)",
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=REPO_ROOT / "examples/run1",
        help="Path to recommender output directory (default: examples/run1)",
    )
    parser.add_argument(
        "--catalog-dir",
        type=Path,
        default=REPO_ROOT / "guardrail-catalog/rails",
        help="Path to guardrail catalog directory (default: guardrail-catalog/rails)",
    )
    parser.add_argument(
        "--policy",
        action="append",
        default=[],
        help=(
            "Policy extraction path as USECASE=PATH (repeatable; e.g., "
            "--policy 01_healthcare_us=/path/to/risk-extraction.json)"
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEMO_DIR / "data",
        help="Output directory for snapshot.json and snapshot.js (default: demo/data)",
    )

    args = parser.parse_args(argv)

    policy_paths = {}
    policy_names = {
        "01_healthcare_us": "RDaSH NHS Foundation Trust: Artificial intelligence (AI) policy",
        "02_banking_eu": "FS-ISAC generative AI policy",
    }
    policy_docs = {
        "01_healthcare_us": "policy_examples/rdash-nhs.md",
        "02_banking_eu": "fs-isac.pdf",
    }

    for policy_spec in args.policy:
        if "=" in policy_spec:
            uc_id, path_str = policy_spec.split("=", 1)
            policy_paths[uc_id.strip()] = Path(path_str)

    try:
        snapshot = build_snapshot(
            args.pipeline_results,
            args.use_cases_dir,
            args.run_dir,
            args.catalog_dir,
            policy_paths,
            policy_names,
            policy_docs,
        )

        snapshot = scrub_environment(snapshot)
        args.out.mkdir(parents=True, exist_ok=True)
        output_file = args.out / "snapshot.json"

        print(f"Writing snapshot to {output_file}...", file=sys.stderr)
        with open(output_file, "w") as f:
            json.dump(snapshot, f, indent=2)

        js_file = args.out / "snapshot.js"
        with open(js_file, "w") as f:
            f.write("window.ASAGO_SNAPSHOT = ")
            json.dump(snapshot, f, separators=(",", ":"))
            f.write(";\n")
        print(f"Wrote {js_file}", file=sys.stderr)

        file_size = output_file.stat().st_size
        file_size_mb = file_size / (1024 * 1024)

        print("\n=== Snapshot Build Complete ===", file=sys.stderr)
        print(f"File: {output_file}", file=sys.stderr)
        print(f"Size: {file_size_mb:.2f} MB ({file_size:,} bytes)", file=sys.stderr)
        print(f"Use cases: {len(snapshot['use_cases'])}", file=sys.stderr)
        print(f"Total attacks: {snapshot['summary']['total_attacks']}", file=sys.stderr)
        print(f"Rails in catalog: {len(snapshot['catalog']['rails'])}", file=sys.stderr)

        for uc in snapshot["use_cases"]:
            print(f"  {uc['id']}: {len(uc['attacks'])} attacks, {len(uc['scenarios'])} scenarios", file=sys.stderr)

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
