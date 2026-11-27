"""Tests for output rails feature."""

import tempfile
from pathlib import Path

import yaml

from asago_guardrails_recommender import catalog, models, recommend

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestChooseOutputRails:
    """Test the choose_output_rails function."""

    def test_injection_detectors_and_judge_for_action_signals(self):
        """Injection signals add the injection detectors on output plus the judge (action harm needs context)."""
        cards = catalog.load_catalog(include_extended=True)
        out = recommend.choose_output_rails([models.Signal("instruction_injection", "essential", "regex")], cards)
        assert out == ["regex_instruction_injection", models.OUTPUT_JUDGE_RAIL_ID]
        assert "regex_action_confirmation" not in out
        assert "hf_classifier_wolf-defender" not in out  # input-only: flags ordinary assistant replies

    def test_exfiltration_uses_use_case_pii_profile(self):
        cards = catalog.load_catalog(include_extended=True)
        sig = [models.Signal("exfiltration_request", "essential", "llm")]
        assert recommend.choose_output_rails(sig, cards) == [models.OUTPUT_JUDGE_RAIL_ID]
        out = recommend.choose_output_rails(sig, cards, use_case_pii=["US_SSN", "NOT_A_CARD"])
        assert out == ["pii_US_SSN", models.OUTPUT_JUDGE_RAIL_ID]

    def test_content_signals_need_no_judge(self):
        cards = catalog.load_catalog(include_extended=True)
        out = recommend.choose_output_rails([models.Signal("harmful_language", "essential", "llm")], cards)
        assert out == ["hf_classifier_guardian-hap"]

    def test_use_case_pii_entities_from_text(self):
        cards = catalog.load_catalog(include_extended=True)
        text = "We store Social Security Numbers and IBAN codes; a pan of soup is not a card number field."
        assert recommend.use_case_pii_entities(text, cards) == ["CREDIT_CARD", "IBAN_CODE", "US_SSN"]
        assert recommend.use_case_pii_entities("a pan and a nie", cards) == []

    def test_pii_signal_adds_pii_card(self):
        """Test that PII signals add matching PII cards."""
        signals = [models.Signal("pii:EMAIL", "essential", "regex")]
        cards = catalog.load_catalog(include_extended=True)

        output_rails = recommend.choose_output_rails(signals, cards)
        # The pii_EMAIL card should be included (even though its placement is 'both')
        assert "pii_EMAIL" in output_rails, f"pii_EMAIL should be in output_rails, got {output_rails}"

    def test_pii_iban_signal_adds_pii_card(self):
        """Test that pii:IBAN_CODE signal adds the matching pii_IBAN_CODE card."""
        signals = [models.Signal("pii:IBAN_CODE", "essential", "regex")]
        cards = catalog.load_catalog(include_extended=True)

        output_rails = recommend.choose_output_rails(signals, cards)
        assert "pii_IBAN_CODE" in output_rails, f"pii_IBAN_CODE should be in output_rails, got {output_rails}"

    def test_pii_iban_lowercase_signal_adds_pii_card(self):
        """Test that pii:iban (lowercase) signal adds the matching pii_IBAN_CODE card via alias."""
        signals = [models.Signal("pii:iban", "essential", "llm")]
        cards = catalog.load_catalog(include_extended=True)

        output_rails = recommend.choose_output_rails(signals, cards)
        assert "pii_IBAN_CODE" in output_rails, f"pii_IBAN_CODE should be in output_rails via alias, got {output_rails}"

    def test_pii_organization_signal_not_in_catalog(self):
        """Test that pii:organization (no card exists) is silently skipped."""
        signals = [models.Signal("pii:organization", "essential", "llm")]
        cards = catalog.load_catalog(include_extended=True)

        output_rails = recommend.choose_output_rails(signals, cards)
        # Should only have the judge rail, no extra cards added
        assert output_rails == [models.OUTPUT_JUDGE_RAIL_ID], f"Only judge should be present, got {output_rails}"

    def test_code_payload_adds_injection_detector(self):
        """Test that code_payload signal adds injection_detector_code."""
        signals = [models.Signal("code_payload", "essential", "regex")]
        cards = catalog.load_catalog(include_extended=True)

        output_rails = recommend.choose_output_rails(signals, cards)
        assert "injection_detector_code" in output_rails

    def test_markup_script_adds_xss_detector(self):
        """Test that markup_script signal adds injection_detector_xss."""
        signals = [models.Signal("markup_script", "essential", "regex")]
        cards = catalog.load_catalog(include_extended=True)

        output_rails = recommend.choose_output_rails(signals, cards)
        assert "injection_detector_xss" in output_rails

    def test_sql_payload_adds_sqli_detector(self):
        """Test that sql_payload signal adds injection_detector_sqli."""
        signals = [models.Signal("sql_payload", "essential", "regex")]
        cards = catalog.load_catalog(include_extended=True)

        output_rails = recommend.choose_output_rails(signals, cards)
        assert "injection_detector_sqli" in output_rails

    def test_template_expr_adds_template_detector(self):
        """Test that template_expr signal adds injection_detector_template."""
        signals = [models.Signal("template_expr", "essential", "regex")]
        cards = catalog.load_catalog(include_extended=True)

        output_rails = recommend.choose_output_rails(signals, cards)
        assert "injection_detector_template" in output_rails


class TestBuildOptionConfigWithOutputRails:
    """Test build_option_config with output rails."""

    def test_output_judge_in_config(self):
        """Test that output judge is added to config when in output_rail_ids."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)

            recommend.build_option_config(
                rail_ids=[models.EXTENDED_RAIL_ID],  # Input judge
                out_dir=out_dir,
                messages=[{"role": "system", "content": "You are helpful."}],
                option_config_id="test-opt1-out",
                output_rail_ids=[models.OUTPUT_JUDGE_RAIL_ID],
            )

            # Read config.yaml
            with open(out_dir / "config.yaml") as f:
                config = yaml.safe_load(f)

            # Check that output judge flow is present
            output_flows = config.get("rails", {}).get("output", {}).get("flows", [])
            assert "self check output" in output_flows, f"Expected 'self check output' in {output_flows}"

            # Check that output prompt is present
            prompts = config.get("prompts", [])
            output_prompts = [p for p in prompts if p.get("task") == "self_check_output"]
            assert len(output_prompts) > 0, "Output prompt should be present"
            assert "{{ bot_response }}" in output_prompts[0]["content"]

    def test_pii_output_in_config(self):
        """Test that PII output detection is added to config."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)

            recommend.build_option_config(
                rail_ids=["pii_EMAIL"],
                out_dir=out_dir,
                messages=[{"role": "system", "content": "You are helpful."}],
                option_config_id="test-email-out",
                output_rail_ids=["pii_EMAIL", models.OUTPUT_JUDGE_RAIL_ID],
            )

            # Read config.yaml
            with open(out_dir / "config.yaml") as f:
                config = yaml.safe_load(f)

            # Check that output flows are present
            output_flows = config.get("rails", {}).get("output", {}).get("flows", [])
            assert "detect sensitive data on output" in output_flows
            assert "self check output" in output_flows

            # Check that sensitive_data_detection.output is configured
            pii_config = config.get("rails", {}).get("config", {}).get("sensitive_data_detection", {})
            output_entities = pii_config.get("output", {}).get("entities", [])
            assert "EMAIL" in output_entities

    def test_injection_output_in_config(self):
        """Test that injection output detection is added to config."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)

            recommend.build_option_config(
                rail_ids=["injection_detector_code"],
                out_dir=out_dir,
                messages=[{"role": "system", "content": "You are helpful."}],
                option_config_id="test-injection-out",
                output_rail_ids=["injection_detector_code"],
            )

            # Read config.yaml
            with open(out_dir / "config.yaml") as f:
                config = yaml.safe_load(f)

            # Check that output injection detection flow is present
            output_flows = config.get("rails", {}).get("output", {}).get("flows", [])
            assert "injection detection" in output_flows

    def test_output_only_yara_no_input_flow(self):
        """Test that output-only YARA doesn't add input flow."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)

            # Build config with injection detector only in output, no input rails
            recommend.build_option_config(
                rail_ids=[],  # No input rails
                out_dir=out_dir,
                messages=[{"role": "system", "content": "You are helpful."}],
                option_config_id="test-output-only",
                output_rail_ids=["injection_detector_code"],
            )

            # Read config.yaml
            with open(out_dir / "config.yaml") as f:
                config = yaml.safe_load(f)

            # Input flows should not include "injection detection on input"
            input_flows = config.get("rails", {}).get("input", {}).get("flows", [])
            assert "injection detection on input" not in input_flows

            # Output flows should include "injection detection" (not "on input")
            output_flows = config.get("rails", {}).get("output", {}).get("flows", [])
            assert "injection detection" in output_flows


class TestOptionSerializationWithOutputRails:
    """Test that Option serialization omits empty output_rails."""

    def test_option_without_output_rails_omits_field(self):
        """Test that empty output_rails is omitted in JSON."""
        option = models.Option(
            rank=1,
            rails=["pii_EMAIL"],
            evidence="core",
            cost_tier=0,
            covers_signals=["pii:EMAIL"],
            rationale="Test",
            config_dir="configs/test",
            test_plan=[],
            output_rails=[],
        )

        serialized = models.to_dict(option)
        assert "output_rails" not in serialized, "Empty output_rails should be omitted"

    def test_option_with_output_rails_includes_field(self):
        """Test that non-empty output_rails is included in JSON."""
        option = models.Option(
            rank=1,
            rails=["pii_EMAIL"],
            evidence="core",
            cost_tier=0,
            covers_signals=["pii:EMAIL"],
            rationale="Test",
            config_dir="configs/test",
            test_plan=[],
            output_rails=["self_check_output_policy"],
        )

        serialized = models.to_dict(option)
        assert "output_rails" in serialized, "Non-empty output_rails should be included"
        assert serialized["output_rails"] == ["self_check_output_policy"]


def test_option2_rationale_names_its_own_rails():
    """Option 2 is Option 1's top rail plus the LLM backup; its rationale must not list Option 1's other rails."""
    cards = catalog.load_catalog()
    attack = models.AttackRecord(
        attack_id="a1",
        short_id="a1",
        use_case="uc",
        artifact_path="",
        scenario_path=None,
        adversarial_text="",
        messages=[],
        attack_turn_index=0,
        injection_surface="",
        narrative_summary="",
    )
    names = ["instruction_injection", "fabricated_evidence", "social_engineering", "tool_misuse"]
    signals = [models.Signal(signal=s, role="essential", source="llm") for s in names]
    candidates = [
        models.Candidate("a1", "hf_classifier_wolf-defender", "core", matched_signals=["instruction_injection"]),
        models.Candidate("a1", "regex_fabricated_evidence", "core", matched_signals=["fabricated_evidence"]),
        models.Candidate(
            "a1", "self_check_input_policy", "core", matched_signals=["social_engineering", "tool_misuse"]
        ),
    ]
    rec = recommend.select(attack, signals, candidates, cards)
    opt1, opt2 = rec.options
    assert opt1.rails == ["hf_classifier_wolf-defender", "regex_fabricated_evidence"]
    assert opt2.rails == ["hf_classifier_wolf-defender", "self_check_input_policy"]
    assert "regex_fabricated_evidence" not in opt2.rationale
    assert "hf_classifier_wolf-defender" in opt2.rationale and "self_check_input_policy" in opt2.rationale
