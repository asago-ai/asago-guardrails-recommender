"""Non-LLM rails added to the catalog (Wolf Defender, regex) and generic output reuse of catalog cards."""

import re

import yaml

from asago_guardrails_recommender import catalog
from asago_guardrails_recommender.models import OUTPUT_JUDGE_RAIL_ID
from asago_guardrails_recommender.recommend import build_option_config


def _cards():
    return catalog.cards_by_id(catalog.load_catalog(include_extended=True))


def test_new_cards_parse_with_placement_and_signals():
    cards = _cards()
    assert cards["hf_classifier_wolf-defender"].detects == ["instruction_injection"]
    assert cards["hf_classifier_wolf-defender"].tier == 1
    for rid, sig in [
        ("regex_instruction_injection", "instruction_injection"),
        ("regex_social_engineering", "social_engineering"),
        ("regex_fabricated_evidence", "fabricated_evidence"),
    ]:
        assert cards[rid].type == "regex_detection" and cards[rid].tier == 0
        assert cards[rid].placement == "both" and cards[rid].detects == [sig]
    assert cards["regex_action_confirmation"].placement == "output"


def test_regex_patterns_compile_and_skip_plain_requests():
    benign = [
        "Can you check the status of my claim from last week?",
        "My doctor already approved the referral, what is the next step?",
        "Please transfer 50 euros to my savings account.",
    ]
    for card in _cards().values():
        if card.type != "regex_detection" or card.placement not in ("input", "both"):
            continue
        rx = [re.compile(p, re.IGNORECASE) for p in card.parameters["patterns"]]
        assert not [s for s in benign if any(r.search(s) for r in rx)], card.id


def _build(tmp_path, rail_ids, output_rail_ids):
    out = build_option_config(
        rail_ids, tmp_path / "cfg", [{"role": "user", "content": "x"}], "t-opt1", output_rail_ids=output_rail_ids
    )
    return yaml.safe_load((out / "config.yaml").read_text())


def test_output_reuse_adds_only_output_flows(tmp_path):
    cfg = _build(
        tmp_path,
        ["hf_classifier_wolf-defender"],
        ["hf_classifier_guardian-hap", "pii_EMAIL", "regex_social_engineering", "regex_action_confirmation"],
    )
    rails = cfg["rails"]
    assert rails["input"]["flows"] == ["hf classifier check windowed input $classifier=wolf-defender"]
    assert set(rails["output"]["flows"]) == {
        "hf classifier check windowed output $classifier=guardian-hap",
        "detect sensitive data on output",
        "regex check output",
    }
    sdd = rails["config"]["sensitive_data_detection"]
    assert sdd["output"]["entities"] == ["EMAIL"] and "input" not in sdd
    rd = rails["config"]["regex_detection"]
    assert "input" not in rd and len(rd["output"]["patterns"]) == 5
    assert set(rails["config"]["hf_classifier"]) == {"wolf-defender", "guardian-hap"}


def test_output_judge_still_supported(tmp_path):
    cfg = _build(tmp_path, ["injection_detector_xss"], [OUTPUT_JUDGE_RAIL_ID, "injection_detector_xss"])
    assert "self check output" in cfg["rails"]["output"]["flows"]
    assert "injection detection" in cfg["rails"]["output"]["flows"]
    assert cfg["rails"]["config"]["injection_detection"]["injections"] == ["xss"]
