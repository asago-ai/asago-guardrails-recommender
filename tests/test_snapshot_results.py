"""Snapshot fields built from a tiny fake run dir: per-option rails, test outcomes, results, benign, policies."""

import json
from pathlib import Path

import pytest
import yaml

from asago_guardrails_recommender.snapshot import (
    REPO_ROOT,
    build_snapshot,
    scrub_environment,
)
from asago_guardrails_recommender.test_rails import run_tables

UC = "01_healthcare_us"
A1 = "scenario:v2:aaaa"
A2 = "scenario:v2:bbbb"
FAKE_HOST = "https://ehr-core.svc.cluster.local:8443/api"
WOLF_FLOW = "hf classifier check windowed input $classifier=wolf-defender"


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data)
    else:
        path.write_text(json.dumps(data))


@pytest.fixture
def fake(tmp_path: Path):
    pipeline = tmp_path / "pipeline_results"
    (pipeline / UC / "artifacts_exhaustive").mkdir(parents=True)
    run = tmp_path / "20261116-170711"
    benign = tmp_path / "benign"

    _write(
        run / "attacks.json",
        [
            {"attack_id": A1, "short_id": "01-aaaa", "use_case": UC, "threat_id": "T10", "artifact_path": ""},
            {"attack_id": A2, "short_id": "01-bbbb", "use_case": UC, "threat_id": "T10", "artifact_path": ""},
        ],
    )
    _write(
        run / "recommendations.json",
        [
            {
                "attack_id": A1,
                "status": "recommended",
                "missing_signals": [],
                "options": [
                    {
                        "rank": 1,
                        "config_id": "opt-1-out",
                        "rails": ["hf_classifier_wolf-defender"],
                        "output_rails": ["self_check_output_policy"],
                        "covers_signals": [],
                        "evidence": "",
                        "rationale": "",
                        "cost_tier": 1,
                        "config_dir": "",
                    },
                    {
                        "rank": 2,
                        "config_id": "opt-2-out",
                        "rails": ["sensitive_data_detection"],
                        "output_rails": ["self_check_output_policy"],
                        "covers_signals": [],
                        "evidence": "",
                        "rationale": "",
                        "cost_tier": 1,
                        "config_dir": "",
                    },
                ],
            },
            {"attack_id": A2, "status": "recommended", "missing_signals": [], "options": []},
        ],
    )
    _write(
        run / "output_test_results.json",
        [
            # A1 rank 1: blocked at input (output stage recorded but not reached)
            {
                "attack_id": A1,
                "short_id": "01-aaaa",
                "option_rank": 1,
                "config_id": "opt-1-out",
                "input_status": "blocked",
                "input_blocking_rail": "hf classifier check windowed input $classifier=wolf-defender",
                "output_status": "blocked",
                "output_blocking_rail": "self check output",
                "attack_success": None,
                "success_reason": None,
                "outcome": "blocked_input",
                "model_reply": "x",
            },
            # A1 rank 2: passed input, blocked at output
            {
                "attack_id": A1,
                "short_id": "01-aaaa",
                "option_rank": 2,
                "config_id": "opt-2-out",
                "input_status": "passed",
                "input_blocking_rail": None,
                "output_status": "blocked",
                "output_blocking_rail": "self check output",
                "attack_success": None,
                "success_reason": None,
                "outcome": "blocked_output",
                "model_reply": "x",
            },
            # A2 rank 1: passes both stages
            {
                "attack_id": A2,
                "short_id": "01-bbbb",
                "option_rank": 1,
                "config_id": "opt-1-out",
                "input_status": "passed",
                "input_blocking_rail": None,
                "output_status": "passed",
                "output_blocking_rail": None,
                "attack_success": True,
                "success_reason": "x",
                "outcome": "attack_succeeded",
                "model_reply": "x",
            },
            # A2 rank 2: input check errored, excluded everywhere
            {
                "attack_id": A2,
                "short_id": "01-bbbb",
                "option_rank": 2,
                "config_id": "opt-2-out",
                "input_status": "error",
                "input_blocking_rail": None,
                "output_status": None,
                "output_blocking_rail": None,
                "attack_success": None,
                "success_reason": None,
                "outcome": "error",
                "model_reply": "x",
            },
        ],
    )
    _write(
        run / "benign_results.json",
        [
            {
                "use_case": UC,
                "request_id": "01-benign-01",
                "kind": "plain",
                "config_id": "c-in-1",
                "blocked": True,
                "blocking_rail": "self check input",
                "error": None,
                "status": "blocked",
                "rails": [],
            },
            {
                "use_case": UC,
                "request_id": "01-benign-02",
                "kind": "borderline",
                "config_id": "c-in-1",
                "blocked": False,
                "blocking_rail": None,
                "error": None,
                "status": "passed",
                "rails": [],
            },
        ],
    )
    _write(
        run / "benign_output_results.json",
        [
            {
                "use_case": UC,
                "request_id": "01-benign-02",
                "kind": "borderline",
                "config_id": "c-out-2",
                "blocked": True,
                "blocking_rail": "detect sensitive data on output",
                "error": None,
                "stage": "output",
                "status": "blocked",
                "rails": [],
            },
            {
                "use_case": UC,
                "request_id": "01-benign-01",
                "kind": "plain",
                "config_id": "c-out-2",
                "blocked": False,
                "blocking_rail": None,
                "error": None,
                "stage": "output",
                "status": "passed",
                "rails": [],
            },
        ],
    )
    _write(
        run / "self_check_policies" / f"{UC}.yaml",
        {
            "use_case": UC,
            "assistant": "HealthHub test assistant",
            "input": ["should not bypass identity verification"],
            "output": ["must not reveal PHI"],
            "model": "qwen-test",
            "source": "cache",
            "context_hash": "abc",
        },
    )
    _write(
        benign / f"{UC}.yaml",
        yaml.safe_dump(
            {
                "use_case": UC,
                "requests": [
                    {
                        "id": "01-benign-01",
                        "kind": "plain",
                        "text": "Where is my appointment?",
                        "why_legitimate": "Routine lookup.",
                    },
                    {
                        "id": "01-benign-02",
                        "kind": "borderline",
                        "text": "Send my visit summary.",
                        "why_legitimate": "Record download.",
                    },
                ],
            }
        ),
    )
    _write(
        benign / "benign_replies.json",
        {
            "01-benign-01": {"rendered": f"Your visit is Thursday. Details at {FAKE_HOST}. " + "x" * 500},
            "01-benign-02": {"rendered": "Here is your summary."},
        },
    )
    return {"pipeline": pipeline, "run": run, "benign": benign}


def _snapshot(fake):
    return build_snapshot(
        fake["pipeline"],
        fake["pipeline"],  # use_cases_dir: no use_case.txt files, so descriptions are empty
        fake["run"],
        REPO_ROOT / "guardrail-catalog/rails",
        {},
        {},
        {},
        fake["benign"],
    )


def _uc(snap):
    return snap["use_cases"][0]


def _attack(snap, attack_id):
    return next(a for a in _uc(snap)["attacks"] if a["attack_id"] == attack_id)


def test_options_split_input_and_output_rails(fake):
    a1 = _attack(_snapshot(fake), A1)
    opt1, opt2 = a1["recommendation"]["options"]
    assert opt1["input_rails"] == ["hf_classifier_wolf-defender"]
    assert opt1["output_rails"] == ["self_check_output_policy"]
    assert opt2["input_rails"] == ["sensitive_data_detection"]
    assert "rails" not in opt1


def test_outcome_mapping_and_normalised_rails(fake):
    snap = _snapshot(fake)
    a1 = _attack(snap, A1)
    r1, r2 = a1["tests"]
    assert r1["option_rank"] == 1
    assert r1["input_status"] == "blocked"
    assert r1["input_blocking_rail"] == "hf_classifier_wolf-defender"
    assert r1["outcome"] == "blocked_input"
    assert r2["input_status"] == "passed"
    assert r2["output_status"] == "blocked"
    assert r2["output_blocking_rail"] == "self_check_output_policy"
    assert r2["outcome"] == "blocked_output"

    a2 = _attack(snap, A2)
    assert [t["outcome"] for t in a2["tests"]] == ["attack_success", "error"]


def test_results_are_per_use_case_and_equal_run_tables(fake):
    snap = _snapshot(fake)
    assert "results" not in snap
    expected = json.loads(json.dumps(run_tables(fake["run"], use_case=UC)))
    assert json.loads(json.dumps(_uc(snap)["results"])) == expected
    # the fixture: rank 1 blocked one at input, rank 2 blocked the other at output, error excluded
    assert expected["options"]["1"]["tested"] == 2
    assert expected["options"]["1"]["blocked_input"] == 1
    assert expected["options"]["2"]["errors"] == 1
    assert expected["options"]["2"]["blocked_output"] == 1
    assert expected["benign"]["input"]["total"] == 2
    assert expected["benign"]["output"]["total"] == 2


def test_benign_requests_and_blocks_grouped(fake):
    benign = {r["id"]: r for r in _uc(_snapshot(fake))["benign"]}
    assert set(benign) == {"01-benign-01", "01-benign-02"}
    assert benign["01-benign-01"]["text"] == "Where is my appointment?"
    assert benign["01-benign-01"]["why_legitimate"] == "Routine lookup."
    assert benign["01-benign-01"]["blocks"] == [
        {"config_id": "c-in-1", "stage": "input", "blocking_rail": "self_check_input_policy"}
    ]
    assert benign["01-benign-02"]["blocks"] == [
        {"config_id": "c-out-2", "stage": "output", "blocking_rail": "sensitive_data_detection"}
    ]
    assert benign["01-benign-01"]["reply_rendered"].endswith("...")
    assert len(benign["01-benign-01"]["reply_rendered"]) == 403  # 400 chars + ellipsis


def test_self_check_policy_present(fake):
    policy = _uc(_snapshot(fake))["self_check_policy"]
    assert policy["assistant"] == "HealthHub test assistant"
    assert policy["input"] == ["should not bypass identity verification"]
    assert policy["output"] == ["must not reveal PHI"]
    assert policy["model"] == "qwen-test"
    assert policy["source"] == "cache"


def test_run_id_catalog_count_and_scrubbing(fake):
    snap = _snapshot(fake)
    assert snap["run_id"] == "20261116-170711"
    assert snap["catalog"]["count"] == len(snap["catalog"]["rails"]) > 0

    scrubbed = json.dumps(scrub_environment(snap))
    assert "svc.cluster.local" not in scrubbed
    assert "ehr-core" not in scrubbed
    assert "<redacted-host>" in scrubbed


def test_provenance_paths_are_relative_to_pipeline_results(tmp_path):
    """Battery source_file and scenario run_dir are recorded relative to --pipeline-results, not as local paths."""
    from asago_guardrails_recommender.snapshot import load_battery, load_scenario_funnel

    run = tmp_path / "results_demo" / "uc1" / "scenarios_exhaustive" / "run-a"
    run.mkdir(parents=True)
    (run / "threat-surface.yaml").write_text("entries: []\n")
    (run / "finalization-inventory.json").write_text('{"admission_decisions": []}')
    root = tmp_path / "results_demo"

    battery = load_battery("uc1", root)
    funnel = load_scenario_funnel("uc1", root)
    assert battery["source_file"] == "uc1/scenarios_exhaustive/run-a/threat-surface.yaml"
    assert funnel["run_dir"] == "uc1/scenarios_exhaustive/run-a"
    assert str(tmp_path) not in json.dumps([battery, funnel])
