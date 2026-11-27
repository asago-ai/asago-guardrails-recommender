"""NeMo fails closed with "I'm sorry, an internal error has occurred." when a rail cannot run.
test_request must record that as an error, not as a block, for every kind of check."""

import json

import pytest

from asago_guardrails_recommender import test_rails

FAIL_CLOSED_BODY = {
    "status": "blocked",
    "rail": "hf_classifier_wolf-defender",
    "messages": [{"role": "assistant", "content": "I'm sorry, an internal error has occurred."}],
}


class _FakeResponse:
    def __init__(self, body, status_code=200):
        self._body = body
        self.status_code = status_code
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self):
        return self._body


def _post_returning(monkeypatch, body, status_code=200):
    monkeypatch.setattr(test_rails.requests, "post", lambda *a, **k: _FakeResponse(body, status_code))


@pytest.mark.parametrize("kind", ["attack_input", "attack_output", "benign_input", "benign_output"])
def test_internal_error_is_error_not_block(monkeypatch, kind):
    # Each record kind goes through the same test_request call, so one assertion per kind.
    _post_returning(monkeypatch, FAIL_CLOSED_BODY)
    request = {"guardrails": {"config_id": f"cfg-{kind}"}, "messages": []}
    status, rail, _latency, error = test_rails.test_request(request, "http://nemo.invalid", 5)
    assert status == "error"
    assert rail is None
    assert error == "rail internal error (hf_classifier_wolf-defender)"


def test_internal_error_without_rail_name_uses_unknown(monkeypatch):
    body = {"status": "blocked", "messages": [{"content": "I'm sorry, an internal error has occurred."}]}
    _post_returning(monkeypatch, body)
    status, _rail, _latency, error = test_rails.test_request({"guardrails": {}}, "http://nemo.invalid", 5)
    assert status == "error"
    assert error == "rail internal error (unknown)"


def test_normal_block_still_blocked(monkeypatch):
    body = {"status": "blocked", "rail": "regex_instruction_injection", "messages": [{"content": "I can't help."}]}
    _post_returning(monkeypatch, body)
    status, rail, _latency, error = test_rails.test_request({"guardrails": {}}, "http://nemo.invalid", 5)
    assert (status, rail, error) == ("blocked", "regex_instruction_injection", None)


def test_passed_still_passed(monkeypatch):
    _post_returning(monkeypatch, {"status": "passed"})
    status, rail, _latency, error = test_rails.test_request({"guardrails": {}}, "http://nemo.invalid", 5)
    assert (status, rail, error) == ("passed", None, None)


def test_internal_error_excluded_from_benign_rates():
    records = [
        {"status": "error", "blocked": False, "config_id": "c", "kind": "plain"},
        {"status": "blocked", "blocked": True, "config_id": "c", "kind": "plain"},
        {"status": "passed", "blocked": False, "config_id": "c", "kind": "plain"},
    ]
    tallies = test_rails._tally(records, lambda r: r["config_id"])
    assert tallies["c"]["total"] == 2
    assert tallies["c"]["blocked"] == 1
    assert tallies["c"]["errors"] == 1
