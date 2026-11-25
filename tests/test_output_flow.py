"""Offline tests for the input+output test flow (test --with-output)."""

import json
from pathlib import Path

import pytest

from asago_guardrails_recommender import attacks, test_rails
from asago_guardrails_recommender.models import Option, Recommendation, config_name
from asago_guardrails_recommender.recommend import _generate_test_plan

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def attack():
    """A real attack with a detector_rubric from the examples."""
    atks = attacks.load_attacks(pipeline_results_path=REPO_ROOT / "examples/pipeline_results")
    return next(a for a in atks if a.detector_rubric)


def _rec(attack, rails=("hf_classifier_prompt-injection",)):
    option = Option(
        rank=1,
        rails=list(rails),
        evidence="core",
        cost_tier=1,
        covers_signals=[],
        rationale="test",
        output_rails=["self_check_output_policy"],
        config_id=f"{attack.short_id}-opt1-out",
    )
    return Recommendation(
        attack_id=attack.attack_id,
        short_id=attack.short_id,
        use_case=attack.use_case,
        signals=[],
        options=[option],
        status="recommended",
    )


class _FakeResponse:
    def __init__(self, status):
        self.status_code = 200
        self._status = status
        self.text = ""

    def json(self):
        return {"status": self._status, "rail": "some rail" if self._status == "blocked" else None}


def _run(monkeypatch, tmp_path, attack, input_status, output_status, judge_reply="", reply="Submitted."):
    """Run _run_output_flow with mocked NeMo and LLM; return (results row, NeMo request bodies, LLM calls)."""
    requests_sent = []
    llm_calls = []

    def fake_post(url, json=None, timeout=None):
        requests_sent.append(json)
        stage = json["guardrails"]["rail_types"][0]
        return _FakeResponse(input_status if stage == "input" else output_status)

    def fake_chat(messages, model, base_url, **kwargs):
        llm_calls.append(messages)
        return reply if len(llm_calls) == 1 else judge_reply

    monkeypatch.setattr(test_rails.requests, "post", fake_post)
    monkeypatch.setattr(test_rails.llm, "chat", fake_chat)
    test_rails._run_output_flow(
        [_rec(attack)],
        {attack.attack_id: attack},
        tmp_path,
        "model",
        "http://nemo",
        "http://llm",
        5,
        None,
        None,
        dry_run=False,
        no_store=True,
    )
    rows = json.loads((tmp_path / "output_test_results.json").read_text())
    assert len(rows) == 1
    return rows[0], requests_sent, llm_calls


class TestOutcomes:
    def test_input_blocked_output_would_block(self, monkeypatch, tmp_path, attack):
        row, _, _ = _run(monkeypatch, tmp_path, attack, "blocked", "blocked")
        assert row["outcome"] == "blocked_input"
        assert row["output_status"] == "blocked"

    def test_input_passed_output_blocked(self, monkeypatch, tmp_path, attack):
        row, _, llm_calls = _run(monkeypatch, tmp_path, attack, "passed", "blocked")
        assert row["outcome"] == "blocked_output"
        assert len(llm_calls) == 1  # model reply only, no success judge

    def test_attack_succeeded(self, monkeypatch, tmp_path, attack):
        row, _, _ = _run(monkeypatch, tmp_path, attack, "passed", "passed", '{"success": true, "reason": "x"}')
        assert row["outcome"] == "attack_succeeded"
        assert row["attack_success"] is True

    def test_model_refused(self, monkeypatch, tmp_path, attack):
        row, _, _ = _run(monkeypatch, tmp_path, attack, "passed", "passed", '{"success": false, "reason": "x"}')
        assert row["outcome"] == "model_refused"

    def test_unparseable_judge(self, monkeypatch, tmp_path, attack):
        row, _, _ = _run(monkeypatch, tmp_path, attack, "passed", "passed", "not json")
        assert row["outcome"] == "unknown"

    def test_model_error(self, monkeypatch, tmp_path, attack):
        def failing_chat(*args, **kwargs):
            raise RuntimeError("down")

        monkeypatch.setattr(test_rails.requests, "post", lambda url, json=None, timeout=None: _FakeResponse("passed"))
        monkeypatch.setattr(test_rails.llm, "chat", failing_chat)
        test_rails._run_output_flow(
            [_rec(attack)],
            {attack.attack_id: attack},
            tmp_path,
            "m",
            "http://n",
            "http://l",
            5,
            None,
            None,
            dry_run=False,
            no_store=True,
        )
        row = json.loads((tmp_path / "output_test_results.json").read_text())[0]
        assert row["outcome"] == "error"
        assert row["model_reply"] is None


class TestRequests:
    def test_request_bodies(self, monkeypatch, tmp_path, attack):
        _, sent, llm_calls = _run(monkeypatch, tmp_path, attack, "passed", "blocked", reply="Done.")
        input_req, output_req = sent
        out_id = config_name(f"{attack.short_id}-opt1-out")
        assert input_req["guardrails"] == {"config_id": out_id, "rail_types": ["input"]}
        assert input_req["messages"] == [{"role": "user", "content": attack.adversarial_text}]
        assert output_req["guardrails"] == {"config_id": out_id, "rail_types": ["output"]}
        assert output_req["messages"] == [
            {"role": "user", "content": attack.adversarial_text},
            {"role": "assistant", "content": "Done."},
        ]
        model_messages = llm_calls[0]
        assert model_messages[0]["role"] == "system"
        assert model_messages[-1] == {"role": "user", "content": attack.adversarial_text}

    def test_request_without_rail_types_unchanged(self, monkeypatch):
        sent = []
        monkeypatch.setattr(
            test_rails.requests,
            "post",
            lambda url, json=None, timeout=None: sent.append(json) or _FakeResponse("passed"),
        )
        body = {"model": "m", "messages": [], "guardrails": {"config_id": "c"}}
        test_rails.test_request(body, "http://n", 5)
        assert sent == [body]


class TestJudgeParsing:
    def test_code_fences(self):
        assert test_rails._parse_judge_response('```json\n{"success": true, "reason": "r"}\n```') == (True, "r")

    def test_unparseable(self):
        assert test_rails._parse_judge_response("nope")[0] is None


def test_two_rail_option_tests_out_config():
    option = Option(
        rank=1,
        rails=["rail_a", "rail_b"],
        evidence="core",
        cost_tier=1,
        covers_signals=[],
        rationale="t",
        output_rails=["self_check_output_policy"],
        config_id="01-abc-opt1-out",
    )
    combined = next(t for t in _generate_test_plan(option, "01-abc") if t["label"] == "combined")
    assert combined["config_id"] == config_name("01-abc-opt1-out")


class TestBaselineReplies:
    """--baseline-replies: output rails check the judged baseline reply; no LLM calls at all."""

    def _run(self, monkeypatch, tmp_path, attack, output_status, replies):
        sent = []

        def fake_post(url, json=None, timeout=None):
            sent.append(json)
            return _FakeResponse("passed" if json["guardrails"]["rail_types"][0] == "input" else output_status)

        def no_llm(*args, **kwargs):
            raise AssertionError("LLM must not be called with baseline replies")

        monkeypatch.setattr(test_rails.requests, "post", fake_post)
        monkeypatch.setattr(test_rails.llm, "chat", no_llm)
        test_rails._run_output_flow(
            [_rec(attack)],
            {attack.attack_id: attack},
            tmp_path,
            "model",
            "http://nemo",
            None,
            5,
            None,
            None,
            dry_run=False,
            no_store=True,
            baseline_replies=replies,
        )
        return json.loads((tmp_path / "output_test_results.json").read_text())[0], sent

    def test_rendered_reply_sent_and_outcome_from_baseline(self, monkeypatch, tmp_path, attack):
        rendered = '[tool call] submit_insurance_claim({"amount": 6200})'
        replies = {attack.attack_id: {"outcome": "attack_succeeded", "rendered": rendered}}
        row, sent = self._run(monkeypatch, tmp_path, attack, "passed", replies)
        assert sent[-1]["messages"][-1] == {"role": "assistant", "content": rendered}
        assert row["outcome"] == "attack_succeeded"

    def test_output_blocked(self, monkeypatch, tmp_path, attack):
        replies = {attack.attack_id: {"outcome": "attack_succeeded", "rendered": "[tool call] x({})"}}
        row, _ = self._run(monkeypatch, tmp_path, attack, "blocked", replies)
        assert row["outcome"] == "blocked_output"

    def test_missing_reply_is_error(self, monkeypatch, tmp_path, attack):
        row, _ = self._run(monkeypatch, tmp_path, attack, "passed", {})
        assert row["outcome"] == "error"
