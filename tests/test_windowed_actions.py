"""Tests for the windowed HF classifier actions in guardrail-catalog/actions.py.

nemoguardrails, torch and transformers are not needed locally: they are stubbed in sys.modules
before the actions file is loaded, and the classifier is a fake pipeline.
"""

import asyncio
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

ACTIONS_PATH = Path(__file__).resolve().parents[1] / "guardrail-catalog" / "actions.py"
INJECTION_MARK = "ATTACK"
TOKENIZER_ERROR = "Tokenizer class TokenizersBackend does not exist or is not currently imported."


class _Outcome:
    def __init__(self, kind: str):
        self.kind = kind

    @classmethod
    def allow(cls):
        return cls("allow")

    @classmethod
    def block(cls):
        return cls("block")

    def __eq__(self, other):
        return isinstance(other, _Outcome) and other.kind == self.kind


def _install_stubs(monkeypatch):
    nemo = types.ModuleType("nemoguardrails")
    actions_mod = types.ModuleType("nemoguardrails.actions")
    actions_mod.action = lambda *a, **k: lambda f: f
    rail_outcome = types.ModuleType("nemoguardrails.actions.rail_outcome")
    rail_outcome.RailOutcome = _Outcome
    http = types.ModuleType("nemoguardrails.http")
    http.HTTPClient = object
    torch = types.ModuleType("torch")

    class AcceleratorError(Exception):
        pass

    torch.AcceleratorError = AcceleratorError
    for name, mod in {
        "nemoguardrails": nemo,
        "nemoguardrails.actions": actions_mod,
        "nemoguardrails.actions.rail_outcome": rail_outcome,
        "nemoguardrails.http": http,
        "torch": torch,
    }.items():
        monkeypatch.setitem(sys.modules, name, mod)


def _load_actions(monkeypatch):
    _install_stubs(monkeypatch)
    spec = importlib.util.spec_from_file_location("catalog_actions_under_test", ACTIONS_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "_CLASSIFIERS", {})
    return mod


def _fake_pipe(score_for_attack: float = 0.99, calls: list | None = None):
    """Returns every label's score. Text containing INJECTION_MARK gets injection=score_for_attack."""

    def pipe(text):
        if calls is not None:
            calls.append(text)
        p = score_for_attack if INJECTION_MARK in text else 0.01
        return [{"label": "benign", "score": 1 - p}, {"label": "injection", "score": p}]

    return pipe


def _config(threshold: float = 0.5, blocked=("injection",)):
    entry = SimpleNamespace(model="org/fake-classifier", threshold=threshold, blocked_labels=list(blocked))
    return SimpleNamespace(rails=SimpleNamespace(config=SimpleNamespace(hf_classifier={"wolf-defender": entry})))


def _long_text_attack_in_second_window() -> str:
    # window 1 = [0, 2500), window 2 = [2000, 4000): the marker at 3000 is only in window 2.
    return "a" * 3000 + INJECTION_MARK + "b" * 1000


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def actions(monkeypatch):
    mod = _load_actions(monkeypatch)
    # Serve the fake pipeline for any model id.
    calls: list[str] = []
    state = {"pipe": _fake_pipe(calls=calls), "calls": calls}
    mod.real_load = mod._load_classifier  # the loader tests exercise the real function
    monkeypatch.setattr(mod, "_load_classifier", lambda model_id: state["pipe"])
    mod.state = state
    return mod


def test_long_input_injection_only_in_second_window_is_blocked(actions):
    text = _long_text_attack_in_second_window()
    result = _run(
        actions.hf_classifier_check_input_windowed(
            classifier="wolf-defender", config=_config(), context={"user_message": text}
        )
    )
    assert result == _Outcome.block()
    # Blocked on the second window: both windows were classified.
    assert len(actions.state["calls"]) == 2


def test_benign_long_input_passes_and_every_window_is_classified(actions):
    text = "hello there. " * 400  # ~5200 chars -> 3 windows
    result = _run(
        actions.hf_classifier_check_input_windowed(
            classifier="wolf-defender", config=_config(), context={"user_message": text}
        )
    )
    assert result == _Outcome.allow()
    assert len(actions.state["calls"]) == 3


def test_short_benign_input_passes(actions):
    result = _run(
        actions.hf_classifier_check_input_windowed(
            classifier="wolf-defender", config=_config(), context={"user_message": "hello"}
        )
    )
    assert result == _Outcome.allow()


def test_empty_input_allowed_without_loading(actions):
    result = _run(actions.hf_classifier_check_input_windowed(classifier="wolf-defender", config=_config(), context={}))
    assert result == _Outcome.allow()
    assert actions.state["calls"] == []


@pytest.mark.parametrize(
    "score, threshold, expected",
    [
        (0.5, 0.5, _Outcome.block()),  # exactly at threshold is blocked (>=)
        (0.4999, 0.5, _Outcome.allow()),
        (0.3, 0.3, _Outcome.block()),
    ],
)
def test_threshold_boundary(actions, score, threshold, expected):
    actions.state["pipe"] = _fake_pipe(score_for_attack=score)
    result = _run(
        actions.hf_classifier_check_input_windowed(
            classifier="wolf-defender",
            config=_config(threshold=threshold),
            context={"user_message": INJECTION_MARK},
        )
    )
    assert result == expected


def test_blocked_label_not_in_blocked_labels_is_allowed(actions):
    actions.state["pipe"] = lambda text: [{"label": "benign", "score": 0.01}, {"label": "other", "score": 0.99}]
    result = _run(
        actions.hf_classifier_check_input_windowed(
            classifier="wolf-defender", config=_config(), context={"user_message": "x"}
        )
    )
    assert result == _Outcome.allow()


def test_output_twin_classifies_bot_message_per_window(actions):
    bot = "y" * 3000 + INJECTION_MARK + "z" * 1000  # marker only in window 2
    result = _run(
        actions.hf_classifier_check_output_windowed(
            classifier="wolf-defender",
            config=_config(),
            context={"user_message": "ignored", "bot_message": bot},
        )
    )
    assert result == _Outcome.block()
    assert len(actions.state["calls"]) == 2


def test_output_twin_ignores_user_message(actions):
    result = _run(
        actions.hf_classifier_check_output_windowed(
            classifier="wolf-defender",
            config=_config(),
            context={"user_message": INJECTION_MARK, "bot_message": "safe reply"},
        )
    )
    assert result == _Outcome.allow()


def test_output_twin_uses_model_name_when_classifier_is_unresolved(actions):
    result = _run(
        actions.hf_classifier_check_output_windowed(
            classifier="$classifier",
            model_name="wolf-defender",
            config=_config(),
            context={"bot_message": INJECTION_MARK},
        )
    )
    assert result == _Outcome.block()


def test_unknown_classifier_raises(actions):
    with pytest.raises(ValueError, match="Unknown classifier"):
        _run(
            actions.hf_classifier_check_input_windowed(
                classifier="nope", config=_config(), context={"user_message": "x"}
            )
        )


def test_accelerator_error_halves_windows_and_retries(actions, monkeypatch):
    failures = {"left": 1}

    def flaky_pipe(text):
        if failures["left"] and len(text) > 1000:
            failures["left"] -= 1
            raise actions.AcceleratorError("oom")
        return [{"label": "benign", "score": 1.0}]

    actions.state["pipe"] = flaky_pipe
    result = _run(
        actions.hf_classifier_check_input_windowed(
            classifier="wolf-defender", config=_config(), context={"user_message": "a" * 3000}
        )
    )
    assert result == _Outcome.allow()
    assert failures["left"] == 0


# --- Loader: pipeline path and tokenizer.json fallback -------------------------------------


def test_loader_uses_pipeline_when_it_loads(actions, monkeypatch):
    seen = {}
    fake_transformers = types.ModuleType("transformers")

    def pipeline(task, model, truncation, top_k):
        seen.update(task=task, model=model, truncation=truncation, top_k=top_k)
        return _fake_pipe()

    fake_transformers.pipeline = pipeline
    monkeypatch.setitem(sys.modules, "transformers", fake_transformers)
    monkeypatch.setattr(actions, "_CLASSIFIERS", {})

    clf = actions.real_load("org/model")
    assert seen == {"task": "text-classification", "model": "org/model", "truncation": True, "top_k": None}
    assert actions.real_load("org/model") is clf  # cached per model id


def test_loader_falls_back_to_tokenizer_json_on_tokenizer_error(actions, monkeypatch, tmp_path, caplog):
    model_id = "org/wolf"
    (tmp_path / "tokenizer.json").write_text("{}")
    (tmp_path / "tokenizer_config.json").write_text(
        '{"tokenizer_class": "TokenizersBackend", "cls_token": "[CLS]", "sep_token": "[SEP]",'
        ' "pad_token": {"content": "[PAD]"}, "extra_special_tokens": ["x"], "model_max_length": 8192}'
    )
    tokenizer_kwargs = {}
    fallback_calls = []

    class FakeTokenizer:
        def __init__(self, tokenizer_file, **kwargs):
            tokenizer_kwargs.update(tokenizer_file=tokenizer_file, **kwargs)

    fake_transformers = types.ModuleType("transformers")
    fake_transformers.PreTrainedTokenizerFast = FakeTokenizer
    fake_transformers.AutoModelForSequenceClassification = SimpleNamespace(
        from_pretrained=lambda mid: fallback_calls.append(("model", mid)) or "MODEL"
    )

    def pipeline(task, model, truncation, top_k, tokenizer=None):
        if tokenizer is None:
            raise ValueError(TOKENIZER_ERROR)
        fallback_calls.append(("pipeline", model, model, tokenizer is not None))
        return _fake_pipe()

    fake_transformers.pipeline = pipeline
    fake_hub = types.ModuleType("huggingface_hub")
    fake_hub.hf_hub_download = lambda repo, filename: str(tmp_path / filename)
    monkeypatch.setitem(sys.modules, "transformers", fake_transformers)
    monkeypatch.setitem(sys.modules, "huggingface_hub", fake_hub)
    monkeypatch.setattr(actions, "_CLASSIFIERS", {})

    with caplog.at_level("INFO"):
        clf = actions.real_load(model_id)

    assert callable(clf)
    assert ("model", model_id) in fallback_calls
    assert tokenizer_kwargs["tokenizer_file"] == str(tmp_path / "tokenizer.json")
    # Only the standard special tokens are passed; the list-valued extra_special_tokens is dropped.
    assert tokenizer_kwargs == {
        "tokenizer_file": str(tmp_path / "tokenizer.json"),
        "cls_token": "[CLS]",
        "sep_token": "[SEP]",
        "pad_token": "[PAD]",
    }
    assert "fallback path" in caplog.text


def test_loader_reraises_unrelated_value_error(actions, monkeypatch):
    fake_transformers = types.ModuleType("transformers")

    def pipeline(*args, **kwargs):
        raise ValueError("something else broke")

    fake_transformers.pipeline = pipeline
    monkeypatch.setitem(sys.modules, "transformers", fake_transformers)
    monkeypatch.setattr(actions, "_CLASSIFIERS", {})
    with pytest.raises(ValueError, match="something else"):
        actions.real_load("org/model")
