"""Tests for probe message extraction in test_rails."""

from dataclasses import replace
from pathlib import Path

import pytest

from asago_guardrails_recommender import attacks, test_rails

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def sample_attack():
    """Load a sample attack from examples/pipeline_results."""
    atks = attacks.load_attacks(pipeline_results_path=REPO_ROOT / "examples/pipeline_results")
    assert len(atks) > 0, "No attacks loaded"
    return atks[0]


class TestGetMessagesForMode:
    """Test _get_messages_for_mode function."""

    def test_attack_mode_returns_single_user_message(self, sample_attack):
        """Test that 'attack' mode returns a single user message with adversarial_text."""
        messages = test_rails._get_messages_for_mode(sample_attack, "attack")

        assert isinstance(messages, list)
        assert len(messages) == 1
        assert messages[0]["role"] == "user"
        assert messages[0]["content"] == sample_attack.adversarial_text

    def test_attack_mode_filters_from_full_conversation(self, sample_attack):
        """Test that 'attack' mode sends only attack turn, not full conversation."""
        attack_messages = test_rails._get_messages_for_mode(sample_attack, "attack")
        all_messages = test_rails._get_messages_for_mode(sample_attack, "all")

        # attack mode should have 1 message, all mode should have more
        assert len(attack_messages) == 1
        assert len(all_messages) > 1

    def test_all_mode_returns_full_conversation(self, sample_attack):
        """Test that 'all' mode returns the full filtered conversation."""
        messages = test_rails._get_messages_for_mode(sample_attack, "all")

        assert isinstance(messages, list)
        assert len(messages) > 1  # Should have multiple messages
        assert messages == sample_attack.messages

    def test_injection_surface_not_user_turn_raises_error(self, sample_attack):
        """Test that non-user_turn injection_surface raises ValueError."""
        # Replace injection_surface with an unsupported value
        bad_attack = replace(sample_attack, injection_surface="tool_return")

        with pytest.raises(ValueError) as exc_info:
            test_rails._get_messages_for_mode(bad_attack, "attack")

        assert "injection_surface" in str(exc_info.value)
        assert "tool_return" in str(exc_info.value)

    def test_empty_adversarial_text_raises_error(self, sample_attack):
        """Test that empty adversarial_text raises ValueError."""
        bad_attack = replace(sample_attack, adversarial_text="")

        with pytest.raises(ValueError) as exc_info:
            test_rails._get_messages_for_mode(bad_attack, "attack")

        assert "adversarial_text is empty" in str(exc_info.value)

    def test_invalid_mode_raises_error(self, sample_attack):
        """Test that an invalid mode raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            test_rails._get_messages_for_mode(sample_attack, "invalid_mode")

        assert "Unknown mode" in str(exc_info.value)

    def test_user_turn_injection_surface_works(self, sample_attack):
        """Test that user_turn injection_surface is accepted."""
        # Ensure injection_surface is user_turn (if not already)
        attack_with_user_turn = replace(sample_attack, injection_surface="user_turn")

        # Should not raise
        messages = test_rails._get_messages_for_mode(attack_with_user_turn, "attack")
        assert len(messages) == 1
        assert messages[0]["role"] == "user"
