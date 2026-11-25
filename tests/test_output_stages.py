"""Output stages: placement and output_flow come from output_stages.yaml, cards stay unmodified."""

import copy
import dataclasses

import pytest
import yaml

from asago_guardrails_recommender import catalog, recommend
from asago_guardrails_recommender.models import RAIL_YAML_DIR


def _cards():
    return catalog.cards_by_id(catalog.load_catalog(include_extended=True))


def _raw(rail_id):
    with open(RAIL_YAML_DIR / f"{rail_id}.yaml") as f:
        return yaml.safe_load(f)


def test_output_rail_ids_have_output_placement_and_flow():
    cards = _cards()
    rail_ids = {rid for rails in recommend.OUTPUT_RAILS_FOR_SIGNAL.values() for rid in rails}
    assert rail_ids
    for rid in sorted(rail_ids):
        assert cards[rid].placement in {"both", "output"}, rid
        assert cards[rid].output_flow, rid


def test_placement_after_output_stages():
    cards = _cards().values()
    counts = {}
    for card in cards:
        counts[card.placement] = counts.get(card.placement, 0) + 1
    assert counts == {"input": 1, "output": 2, "both": 68}


def test_sensitive_data_fragment():
    fragment, flow = recommend._output_stage("pii_EMAIL")
    assert flow == "detect sensitive data on output"
    sdd = fragment["sensitive_data_detection"]
    assert sdd["output"] == {"entities": ["EMAIL"]}
    assert "input" not in sdd
    assert sdd["recognizers"] == _raw("pii_EMAIL")["rails"]["config"]["sensitive_data_detection"]["recognizers"]


def test_injection_fragment():
    fragment, flow = recommend._output_stage("injection_detector_code")
    assert flow == "injection detection"
    assert fragment == {"injection_detection": {"injections": ["code"]}}


def test_hf_classifier_fragment():
    fragment, flow = recommend._output_stage("hf_classifier_wolf-defender")
    assert flow == "hf classifier check windowed output $classifier=wolf-defender"
    assert fragment == {
        "hf_classifier": {
            "wolf-defender": {
                "blocked_labels": ["injection"],
                "engine": "local",
                "model": "RedHatAI/wolf-defender-prompt-injection",
                "task": "text-classification",
                "threshold": 0.5,
            }
        }
    }


def test_regex_fragment_moves_input_to_output():
    fragment, flow = recommend._output_stage("regex_instruction_injection")
    assert flow == "regex check output"
    rd = fragment["regex_detection"]
    assert set(rd) == {"output"}
    source = _raw("regex_instruction_injection")["rails"]["config"]["regex_detection"]["input"]
    assert rd["output"] == source
    assert rd["output"]["case_insensitive"] is True


def test_own_output_flow_card_keeps_its_config_and_flow():
    fragment, flow = recommend._output_stage("regex_action_confirmation")
    assert flow == "regex check output"
    assert fragment == _raw("regex_action_confirmation")["rails"]["config"]


def test_card_without_output_flow_raises(monkeypatch):
    index = dict(recommend._catalog_index())
    index["pii_EMAIL"] = dataclasses.replace(index["pii_EMAIL"], output_flow=None)
    monkeypatch.setattr(recommend, "_catalog_index", lambda: index)
    with pytest.raises(ValueError, match="pii_EMAIL"):
        recommend._output_stage("pii_EMAIL")


def test_output_stage_config_does_not_mutate_input():
    rails_config = copy.deepcopy(_raw("pii_EMAIL")["rails"]["config"])
    before = copy.deepcopy(rails_config)
    catalog.output_stage_config("sensitive_data_detection", rails_config)
    assert rails_config == before


def test_cards_without_output_section_except_own_flow_card():
    with_output = set()
    for path in sorted(RAIL_YAML_DIR.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text()) or {}
        if (raw.get("rails") or {}).get("output"):
            with_output.add(path.stem)
    assert with_output == {"regex_action_confirmation"}
