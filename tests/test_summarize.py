"""Offline tests for `test --summarize`: per-run tables reconcile with the result files.

Fake records only; no NeMo server, no network. Output dirs are monkeypatched to tmp_path.
"""

import json

from asago_guardrails_recommender import test_rails
from asago_guardrails_recommender.models import EfficacyRecord, to_dict

WOLF_INPUT = "hf classifier check windowed input $classifier=wolf-defender"
WOLF_OUTPUT = "hf classifier check windowed output $classifier=wolf-defender"
UC_A = "01_healthcare_us"
UC_B = "02_banking_eu"


def _attack(attack_id, rank, input_status, output_status, outcome, input_rail=None, output_rail=None):
    return {
        "attack_id": attack_id,
        "short_id": attack_id,
        "option_rank": rank,
        "config_id": f"{attack_id}-opt{rank}",
        "input_status": input_status,
        "input_blocking_rail": input_rail,
        "model_reply": None,
        "output_status": output_status,
        "output_blocking_rail": output_rail,
        "attack_success": None,
        "success_reason": None,
        "outcome": outcome,
    }


def _benign(request_id, kind, status, blocking_rail=None, config_id="cfg"):
    return {
        "use_case": "uc",
        "request_id": request_id,
        "kind": kind,
        "config_id": config_id,
        "rails": ["pii_EMAIL"],
        "status": status,
        "blocked": status == "blocked",
        "blocking_rail": blocking_rail if status == "blocked" else None,
        "error": "HTTP 500" if status == "error" else None,
    }


def _write_run(run_dir, attacks, benign_in, benign_out):
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "output_test_results.json").write_text(json.dumps(attacks))
    (run_dir / "benign_results.json").write_text(json.dumps(benign_in))
    (run_dir / "benign_output_results.json").write_text(json.dumps(benign_out))
    return run_dir


def _attacks():
    return [
        # rank 1: blocked at input by wolf; its output check still ran and blocked, must not count at output
        _attack("a1", 1, "blocked", "blocked", "blocked_input", WOLF_INPUT, "self check output"),
        # rank 1: passed input, blocked at output
        _attack("a2", 1, "passed", "blocked", "blocked_output", None, "self check output"),
        # rank 1: passed both, attack succeeded
        _attack("a3", 1, "passed", "passed", "attack_succeeded"),
        # rank 2: input check errored: excluded everywhere
        _attack("a4", 2, "error", "passed", "error"),
        # rank 2: input passed, output errored: excluded
        _attack("a5", 2, "passed", "error", "error"),
        # rank 2: passed both, model refused
        _attack("a6", 2, "passed", "passed", "model_refused"),
    ]


def _benign_inputs():
    return [
        _benign("b1", "plain", "blocked", "detect sensitive data on input"),
        _benign("b2", "borderline", "error"),
        _benign("b3", "plain", "passed"),
    ]


def _benign_outputs():
    return [
        _benign("b1", "plain", "blocked", "detect sensitive data on output"),
        _benign("b2", "plain", "passed"),
    ]


def test_flow_names_map_to_catalog_rail_ids():
    assert test_rails.rail_for_flow(WOLF_INPUT) == "hf_classifier_wolf-defender"
    assert test_rails.rail_for_flow(WOLF_OUTPUT) == "hf_classifier_wolf-defender"
    assert test_rails.rail_for_flow("self check input") == "self_check_input_policy"
    assert test_rails.rail_for_flow("self check output") == "self_check_output_policy"
    assert test_rails.rail_for_flow("regex check input") == "regex_detection"
    assert test_rails.rail_for_flow("detect sensitive data on input") == "sensitive_data_detection"
    assert test_rails.rail_for_flow("detect sensitive data on output") == "sensitive_data_detection"
    # already a catalog id, and "no block" values
    assert test_rails.rail_for_flow("hf_classifier_wolf-defender") == "hf_classifier_wolf-defender"
    assert test_rails.rail_for_flow(None) is None
    assert test_rails.rail_for_flow("None") is None


def test_per_option_rank_counts_exclude_errors_and_do_not_double_count(tmp_path):
    run = _write_run(tmp_path / "run", _attacks(), _benign_inputs(), _benign_outputs())
    options = test_rails.run_tables(run)["options"]

    assert options[1] == {
        "tested": 3,
        "blocked_input": 1,
        "output_checked": 2,
        "blocked_output": 1,
        "attack_succeeded": 1,
        "errors": 0,
    }
    # a4 (input error) and a5 (output error) are errors, not tested and not passed
    assert options[2] == {
        "tested": 1,
        "blocked_input": 0,
        "output_checked": 1,
        "blocked_output": 0,
        "attack_succeeded": 0,
        "errors": 2,
    }


def test_per_rail_attribution_uses_normalised_names_and_skips_input_blocked_outputs(tmp_path):
    run = _write_run(tmp_path / "run", _attacks(), _benign_inputs(), _benign_outputs())
    rails = test_rails.run_tables(run)["rails"]

    # a1's output block (self check output) belongs to an attack already blocked at input: not counted
    assert rails["self_check_output_policy"]["attack_output"] == 1
    assert rails["self_check_output_policy"]["attack_input"] == 0
    assert rails["hf_classifier_wolf-defender"]["attack_input"] == 1
    assert rails["hf_classifier_wolf-defender"]["attack_output"] == 0


def test_benign_counts_per_stage_with_errors_excluded(tmp_path):
    run = _write_run(tmp_path / "run", _attacks(), _benign_inputs(), _benign_outputs())
    tables = test_rails.run_tables(run)

    inp = tables["benign"]["input"]
    assert (inp["blocked"], inp["total"], inp["errors"]) == (1, 2, 1)
    assert inp["kinds"]["plain"] == {"blocked": 1, "total": 2}
    assert "borderline" not in inp["kinds"]  # its only call errored
    out = tables["benign"]["output"]
    assert (out["blocked"], out["total"], out["errors"]) == (1, 2, 0)

    rails = tables["rails"]
    assert rails["sensitive_data_detection"]["benign_input"] == 1
    assert rails["sensitive_data_detection"]["benign_output"] == 1


def test_format_lines_and_missing_files(tmp_path):
    run = _write_run(tmp_path / "run", _attacks(), _benign_inputs(), _benign_outputs())
    text = "\n".join(test_rails.format_run_tables(test_rails.run_tables(run)))
    assert "Per option rank" in text
    assert "hf_classifier_wolf-defender" in text
    assert "Benign input: 1/2 blocked" in text

    empty = tmp_path / "empty"
    empty.mkdir()
    text = "\n".join(test_rails.format_run_tables(test_rails.run_tables(empty)))
    assert "no output_test_results.json" in text
    assert "Benign input: no benign_results.json" in text


def _member_record():
    # a two-rail config blocked by a flow name: must count as a member of self_check_input_policy
    return EfficacyRecord(
        run_id="r",
        catalog_version="v",
        attack_id="a",
        use_case="uc",
        attack_features={},
        rails=["self_check_input_policy", "regex_detection"],
        option_rank=1,
        level="end_to_end",
        status="blocked",
        blocking_rail="self check input",
        judge_outcome=None,
        latency_ms=1.0,
        timestamp="t",
    )


def test_store_summary_normalises_multi_rail_block_names(tmp_path, monkeypatch):
    monkeypatch.setattr(test_rails, "META_DIR", tmp_path / "meta")
    summaries = test_rails.summarize([_member_record()])

    assert "self check input" not in summaries
    assert summaries["self_check_input_policy"]["blocked_as_member"] == 1
    assert "tested" not in summaries["self_check_input_policy"]


def test_cli_summarize_prints_run_tables_first(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(test_rails, "META_DIR", tmp_path / "meta")
    run = _write_run(tmp_path / "run", _attacks(), _benign_inputs(), _benign_outputs())
    records_path = tmp_path / "records.jsonl"
    records_path.write_text(json.dumps(to_dict(_member_record())) + "\n")
    test_rails.main(["--run-dir", str(run), "--summarize", "--records", str(records_path)])

    out = capsys.readouterr().out
    assert out.index("Per option rank") < out.index("Per rail id") < out.index("Efficacy store")
    assert "Benign output: 1/2 blocked" in out


def test_use_case_filter_partitions_attacks_and_benign(tmp_path):
    run = _write_run(tmp_path / "run", _attacks(), _benign_inputs(), _benign_outputs())
    # attacks carry their use case only in attacks.json; a1-a3 belong to UC_A, a4-a6 to UC_B
    attacks_meta = [{"attack_id": f"a{i}", "use_case": UC_A if i <= 3 else UC_B} for i in range(1, 7)]
    (run / "attacks.json").write_text(json.dumps(attacks_meta))
    uc_of_benign = {"b1": UC_A, "b2": UC_B, "b3": UC_B}
    for name, recs in (("benign_results.json", _benign_inputs()), ("benign_output_results.json", _benign_outputs())):
        for r in recs:
            r["use_case"] = uc_of_benign[r["request_id"]]
        (run / name).write_text(json.dumps(recs))

    total = test_rails.run_tables(run)
    per_uc = {uc: test_rails.run_tables(run, use_case=uc) for uc in (UC_A, UC_B)}

    for rank, opt in total["options"].items():
        for key, value in opt.items():
            # a rank absent from one use case contributes zero
            assert sum(per_uc[uc]["options"].get(rank, {}).get(key, 0) for uc in per_uc) == value
    for stage in ("input", "output"):
        for key in ("blocked", "total", "errors"):
            assert sum(per_uc[uc]["benign"][stage][key] for uc in per_uc) == total["benign"][stage][key]
    # the filtered tables keep the same shape
    assert set(per_uc[UC_A]) == set(total) == {"options", "rails", "benign"}
    # an unknown use case selects nothing
    empty = test_rails.run_tables(run, use_case="99_nowhere")
    assert empty["options"] == {}
    assert empty["benign"]["input"]["total"] == 0
