"""Offline tests for the benign false-positive tests (test --benign-requests, --benign-replies).

Fake /v1/checks via monkeypatched requests.post; no network, no cluster.
"""

import json
from pathlib import Path

import pytest
import requests

from asago_guardrails_recommender import test_rails
from asago_guardrails_recommender.models import AttackRecord, Option, Recommendation, to_dict

REPO_ROOT = Path(__file__).resolve().parents[1]
BENIGN_DIR = REPO_ROOT / "examples/benign_requests"


def _entry(label, config_id, rails):
    return {"label": label, "config_id": config_id, "rails": rails}


def _option(rank, rails, config_id, test_plan):
    return Option(
        rank=rank,
        rails=rails,
        evidence="core",
        cost_tier=1,
        covers_signals=[],
        rationale="test",
        output_rails=["self_check_output_policy"],
        config_id=config_id,
        test_plan=test_plan,
    )


def _rec(short_id, use_case, options, status="recommended"):
    return Recommendation(
        attack_id=short_id,
        short_id=short_id,
        use_case=use_case,
        signals=[],
        options=options,
        status=status,
    )


def _recs():
    """A1: option 1 single-rail (atomic config, no -out config), option 2 two-rail (shared -out config plus
    atomic configs). B1 is a gap and must be ignored. C1 is in another use case."""
    a1 = _rec(
        "A1",
        "01_x",
        [
            _option(1, ["r_a"], None, [_entry("single", "a-detector", ["r_a"])]),
            _option(
                2,
                ["r_a", "r_b"],
                "opt-111-out",
                [
                    _entry("combined", "opt-111-out", ["r_a", "r_b"]),
                    _entry("individual_r_a", "a-detector", ["r_a"]),
                    _entry("individual_r_b", "b-detector", ["r_b"]),
                ],
            ),
        ],
    )
    b1 = _rec("B1", "01_x", [_option(1, ["r_z"], None, [_entry("single", "z-detector", ["r_z"])])], status="gap")
    c1 = _rec("C1", "02_y", [_option(1, ["r_c"], None, [_entry("single", "c-detector", ["r_c"])])])
    return [a1, b1, c1]


BENIGN = {
    "01_x": [
        {"id": "01-benign-01", "kind": "plain", "text": "Plain question."},
        {"id": "01-benign-02", "kind": "borderline", "text": "Borderline trigger question."},
    ]
}


class _FakeResponse:
    def __init__(self, status):
        self.status_code = 200
        self._status = status
        self.text = ""

    def json(self):
        return {"status": self._status, "rail": "fake rail" if self._status == "blocked" else None}


@pytest.fixture
def fake_checks(monkeypatch):
    """Fake /v1/checks: blocks any request whose messages contain 'trigger' or 'leak'; records every request."""
    sent = []

    def fake_post(url, json=None, timeout=None):
        sent.append({"url": url, "json": json})
        text = " ".join(m["content"] for m in json["messages"])
        blocked = "trigger" in text or "leak" in text
        return _FakeResponse("blocked" if blocked else "passed")

    monkeypatch.setattr(test_rails.requests, "post", fake_post)
    return sent


def _record(uc, cfg, rails, kind, blocked, status=None):
    """A benign input-stage record, as run_benign_tests writes it."""
    status = status or ("blocked" if blocked else "passed")
    return {
        "use_case": uc,
        "request_id": f"r-{cfg}-{kind}-{blocked}-{status}",
        "kind": kind,
        "config_id": cfg,
        "rails": rails,
        "status": status,
        "blocked": blocked,
        "blocking_rail": None,
        "error": "boom" if status == "error" else None,
    }


# INPUT STAGE


def test_input_configs_are_test_plan_configs():
    configs = test_rails.benign_input_configs(_recs(), "01_x")
    # Every test-plan config of the non-gap attacks in this use case, including the -out combined config.
    assert set(configs) == {"a-detector", "b-detector", "opt-111-out"}
    assert configs["opt-111-out"] == ["r_a", "r_b"]
    # Other use cases and gap recommendations contribute nothing.
    assert "c-detector" not in configs
    assert "z-detector" not in configs
    # Attacks that are not loaded are skipped, as in the attack loop.
    assert test_rails.benign_input_configs(_recs(), "01_x", attack_ids={"B1"}) == {}


def test_each_request_sent_once_per_config_with_user_message_only(fake_checks):
    records = test_rails.run_benign_tests(_recs(), BENIGN, "http://fake", "guard-m", 5)

    assert len(records) == 3 * 2
    assert len(fake_checks) == 6
    seen = set()
    for call in fake_checks:
        body = call["json"]
        cfg = body["guardrails"]["config_id"]
        text = body["messages"][0]["content"]
        # Exactly the payload the attack input test loop sends: no rail_types, one user message.
        assert body == {
            "model": "guard-m",
            "messages": [{"role": "user", "content": text}],
            "guardrails": {"config_id": cfg},
        }
        assert call["url"] == "http://fake/v1/checks"
        seen.add((cfg, text))
    assert len(seen) == 6


def test_blocked_parsing_and_error(monkeypatch):
    def fake_post(url, json=None, timeout=None):
        text = json["messages"][0]["content"]
        if "boom" in text:
            raise requests.ConnectionError("cannot reach http://fake")
        return _FakeResponse("blocked" if "trigger" in text else "passed")

    monkeypatch.setattr(test_rails.requests, "post", fake_post)
    benign = {
        "01_x": [
            {"id": "01-benign-01", "kind": "plain", "text": "trigger here"},
            {"id": "01-benign-02", "kind": "plain", "text": "fine"},
            {"id": "01-benign-03", "kind": "plain", "text": "boom"},
        ]
    }
    records = test_rails.run_benign_tests([_recs()[0]], benign, "http://fake", "m", 5)
    by_id = {r["request_id"]: r for r in records if r["config_id"] == "a-detector"}

    assert by_id["01-benign-01"]["blocked"] is True
    assert by_id["01-benign-01"]["blocking_rail"] == "fake rail"
    assert by_id["01-benign-02"]["blocked"] is False
    assert by_id["01-benign-02"]["blocking_rail"] is None
    assert by_id["01-benign-03"]["status"] == "error"
    assert by_id["01-benign-03"]["blocked"] is False
    assert by_id["01-benign-03"]["error"]
    assert "http://fake" not in by_id["01-benign-03"]["error"]


def test_summary_counts_and_option_distribution():
    records = [
        # a-detector (option 1 of A1): 1 of 4 blocked = 25%, so the >=25% bucket.
        _record("01_x", "a-detector", ["r_a"], "plain", False),
        _record("01_x", "a-detector", ["r_a"], "plain", False),
        _record("01_x", "a-detector", ["r_a"], "borderline", True),
        _record("01_x", "a-detector", ["r_a"], "borderline", False),
        # opt-111-out (option 2 of A1): nothing blocked.
        _record("01_x", "opt-111-out", ["r_a", "r_b"], "plain", False),
        _record("01_x", "opt-111-out", ["r_a", "r_b"], "borderline", False),
        # c-detector has no records, so C1 counts as no data.
    ]
    by_cfg = test_rails.summarize_benign_by_config(records)
    assert by_cfg["a-detector"]["blocked"] == 1
    assert by_cfg["a-detector"]["total"] == 4
    assert by_cfg["a-detector"]["kinds"]["borderline"] == {"blocked": 1, "total": 2}
    assert by_cfg["a-detector"]["kinds"]["plain"] == {"blocked": 0, "total": 2}

    dist = test_rails.option_fp_distribution(_recs(), records)
    assert dist[1] == {"options": 2, "fp_0": 0, "fp_gt_0": 1, "fp_ge_25": 1, "no_data": 1}
    assert dist[2] == {"options": 1, "fp_0": 1, "fp_gt_0": 0, "fp_ge_25": 0, "no_data": 0}

    rail_fp = test_rails.benign_rail_fp(records)
    assert (rail_fp["r_a"]["blocked"], rail_fp["r_a"]["total"]) == (1, 4)
    assert "r_b" not in rail_fp  # two-rail calls are not attributable to one rail

    lines = test_rails.format_benign_summary(_recs(), records)
    assert any(line.startswith("Overall: 1/6") for line in lines)
    assert any("FP>0: 1 (of which >=25%: 1)" in line for line in lines)


def test_error_calls_excluded_from_denominators():
    records = [
        _record("01_x", "a-detector", ["r_a"], "plain", False),
        _record("01_x", "a-detector", ["r_a"], "plain", True),
        _record("01_x", "a-detector", ["r_a"], "plain", False, status="error"),
        _record("01_x", "a-detector", ["r_a"], "plain", False, status="error"),
        # Only errors for opt-111-out: no data, not 0%.
        _record("01_x", "opt-111-out", ["r_a", "r_b"], "plain", False, status="error"),
    ]
    t = test_rails.summarize_benign_by_config(records)["a-detector"]
    assert (t["blocked"], t["total"], t["errors"]) == (1, 2, 2)  # 1/2, not 1/4
    assert t["kinds"]["plain"] == {"blocked": 1, "total": 2}

    dist = test_rails.option_fp_distribution(_recs(), records)
    assert dist[1]["fp_ge_25"] == 1  # 1 blocked of 2 non-error calls = 50%, not 1 of 4
    assert dist[2] == {"options": 1, "fp_0": 0, "fp_gt_0": 0, "fp_ge_25": 0, "no_data": 1}

    rail_fp = test_rails.benign_rail_fp(records)
    assert (rail_fp["r_a"]["blocked"], rail_fp["r_a"]["total"], rail_fp["r_a"]["errors"]) == (1, 2, 2)

    lines = test_rails.format_benign_summary(_recs(), records)
    assert any(line.startswith("Overall: 1/2") and "errors: 3 (excluded)" in line for line in lines)


def test_records_sorted_deterministically(fake_checks):
    recs = _recs()
    benign_fwd = {"01_x": list(BENIGN["01_x"])}
    benign_rev = {"01_x": list(reversed(BENIGN["01_x"]))}
    first = test_rails.run_benign_tests(recs, benign_fwd, "http://fake", "m", 5)
    second = test_rails.run_benign_tests(list(reversed(recs)), benign_rev, "http://fake", "m", 5)
    assert first == second
    keys = [(r["use_case"], r["config_id"], r["request_id"]) for r in first]
    assert keys == sorted(keys)


def test_load_example_files():
    loaded = test_rails.load_benign_requests(BENIGN_DIR)
    assert set(loaded) == {"01_healthcare_us", "02_banking_eu"}
    for reqs in loaded.values():
        assert reqs
        assert [r["id"] for r in reqs] == sorted(r["id"] for r in reqs)
        assert {r["kind"] for r in reqs} <= {"plain", "borderline"}


def test_use_case_must_match_file_name(tmp_path):
    (tmp_path / "02_y.yaml").write_text("use_case: 01_x\nrequests: []\n")
    with pytest.raises(ValueError):
        test_rails.load_benign_requests(tmp_path)


# OUTPUT STAGE


def _replies():
    return {
        "01-benign-01": {"use_case": "01_x", "kind": "plain", "outcome": "benign", "rendered": "Sure, here it is."},
        "01-benign-02": {"use_case": "01_x", "kind": "borderline", "outcome": "benign", "rendered": "leak"},
    }


def test_output_configs_match_output_flow_selection():
    # Only A1 option 2 has output rails and a config_id; option 1 has no config_id, C1 is another use case,
    # B1 is a gap.
    assert test_rails.benign_output_configs(_recs(), "01_x") == {"opt-111-out": ["self_check_output_policy"]}
    assert test_rails.benign_output_configs(_recs(), "02_y") == {}
    assert test_rails.benign_output_configs(_recs(), "01_x", attack_ids={"B1"}) == {}


def test_output_payload_mirrors_output_check(fake_checks):
    records = test_rails.run_benign_output_tests(_recs(), BENIGN, _replies(), "http://fake", "guard-m", 5)

    assert len(fake_checks) == 2  # one output config x two benign requests
    for call in fake_checks:
        body = call["json"]
        assert set(body) == {"model", "messages", "guardrails"}
        assert body["model"] == "guard-m"
        assert body["guardrails"] == {"config_id": "opt-111-out", "rail_types": ["output"]}
        assert [m["role"] for m in body["messages"]] == ["user", "assistant"]
    assert fake_checks[0]["json"]["messages"] == [
        {"role": "user", "content": "Plain question."},
        {"role": "assistant", "content": "Sure, here it is."},
    ]
    assert all(r["stage"] == "output" for r in records)
    by_id = {r["request_id"]: r for r in records}
    assert by_id["01-benign-02"]["blocked"] is True
    assert by_id["01-benign-01"]["blocked"] is False


def test_output_missing_or_mismatched_reply_is_error_not_sent(fake_checks):
    replies = {
        "01-benign-01": {"use_case": "01_x", "rendered": None},  # no rendered text
        "01-benign-02": {"use_case": "02_y", "rendered": "Fine."},  # wrong use case
    }
    records = test_rails.run_benign_output_tests(_recs(), BENIGN, replies, "http://fake", "m", 5)
    assert fake_checks == []
    assert all(r["status"] == "error" for r in records)
    assert all(r["error"] == "no benign reply for this request" for r in records)
    assert all(r["stage"] == "output" for r in records)


def test_output_summary_excludes_errors(fake_checks):
    replies = {"01-benign-01": {"use_case": "01_x", "rendered": "Sure."}}  # 01-benign-02 has no reply
    records = test_rails.run_benign_output_tests(_recs(), BENIGN, replies, "http://fake", "m", 5)
    t = test_rails.summarize_benign_by_config(records)["opt-111-out"]
    assert (t["blocked"], t["total"], t["errors"]) == (0, 1, 1)

    dist = test_rails.option_fp_distribution(_recs(), records, test_rails.option_output_config)
    assert dist[2] == {"options": 1, "fp_0": 1, "fp_gt_0": 0, "fp_ge_25": 0, "no_data": 0}
    # Option 1 has no output config, so it is not counted in the output distribution.
    assert 1 not in dist

    lines = test_rails.format_benign_summary(_recs(), records, "output", test_rails.option_output_config)
    assert any("(output, 1 options)" in line for line in lines)


def test_load_replies_requires_object(tmp_path):
    path = tmp_path / "replies.json"
    path.write_text("[]")
    with pytest.raises(ValueError):
        test_rails.load_benign_replies(path)


# CLI


def _write_run(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "recommendations.json").write_text(json.dumps([to_dict(r) for r in _recs()]))
    attack = AttackRecord(
        attack_id="A1",
        short_id="A1",
        use_case="01_x",
        artifact_path="x",
        scenario_path=None,
        adversarial_text="attack text",
        messages=[{"role": "user", "content": "attack text"}],
        attack_turn_index=0,
        injection_surface="user_turn",
        narrative_summary="n",
    )
    (run_dir / "attacks.json").write_text(json.dumps([to_dict(attack)]))
    benign_dir = tmp_path / "benign"
    benign_dir.mkdir()
    (benign_dir / "01_x.yaml").write_text(
        "use_case: 01_x\nrequests:\n"
        "  - id: 01-benign-01\n    kind: plain\n    text: 'Plain question.'\n"
        "  - id: 01-benign-02\n    kind: borderline\n    text: 'Borderline trigger question.'\n"
    )
    return run_dir, benign_dir


def test_cli_writes_benign_results(tmp_path, fake_checks):
    run_dir, benign_dir = _write_run(tmp_path)

    test_rails.main(
        ["--run-dir", str(run_dir), "--nemo-url", "http://fake", "--benign-requests", str(benign_dir), "--no-store"]
    )

    out = json.loads((run_dir / "benign_results.json").read_text())
    assert len(out) == 6  # 3 input configs x 2 requests
    assert out == sorted(out, key=lambda r: (r["use_case"], r["config_id"], r["request_id"]))
    assert sum(1 for r in out if r["blocked"]) == 3  # the borderline request, once per config
    assert not (run_dir / "benign_output_results.json").exists()


def test_cli_writes_benign_output_results(tmp_path, fake_checks):
    run_dir, benign_dir = _write_run(tmp_path)
    replies_path = tmp_path / "benign_replies.json"
    replies_path.write_text(json.dumps(_replies()))

    test_rails.main(
        [
            "--run-dir",
            str(run_dir),
            "--nemo-url",
            "http://fake",
            "--benign-requests",
            str(benign_dir),
            "--benign-replies",
            str(replies_path),
            "--no-store",
        ]
    )

    out = json.loads((run_dir / "benign_output_results.json").read_text())
    assert [(r["request_id"], r["config_id"], r["blocked"], r["stage"]) for r in out] == [
        ("01-benign-01", "opt-111-out", False, "output"),
        ("01-benign-02", "opt-111-out", True, "output"),
    ]
    # The input stage still ran alongside it.
    assert len(json.loads((run_dir / "benign_results.json").read_text())) == 6


def test_cli_benign_replies_requires_benign_requests(tmp_path):
    run_dir, _ = _write_run(tmp_path)
    replies_path = tmp_path / "benign_replies.json"
    replies_path.write_text("{}")
    with pytest.raises(SystemExit):
        test_rails.main(["--run-dir", str(run_dir), "--nemo-url", "http://fake", "--benign-replies", str(replies_path)])
