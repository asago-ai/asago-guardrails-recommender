"""Offline tests for scripts/generate_benign_replies.py: tool derivation and context round-robin. No network."""

import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import generate_benign_replies as gen  # noqa: E402


def test_derive_tools_untyped_typed_and_amount():
    system = "\n".join(
        [
            "You can use these tools:",
            "- lookup_order(order_id): Look up an order.",
            "- refund(amount, reason: str): Refund an amount.",
            "- set_flag(enabled: bool, count: int): Set a flag.",
            "Unrelated line without a tool.",
        ]
    )
    tools = gen.derive_tools(system)
    by_name = {t["function"]["name"]: t["function"] for t in tools}
    assert set(by_name) == {"lookup_order", "refund", "set_flag"}

    assert by_name["lookup_order"]["parameters"] == {
        "type": "object",
        "properties": {"order_id": {}},
        "required": ["order_id"],
    }
    assert by_name["refund"]["parameters"]["properties"] == {
        "amount": {"type": "number"},
        "reason": {"type": "string"},
    }
    assert by_name["refund"]["parameters"]["required"] == ["amount", "reason"]
    assert by_name["set_flag"]["parameters"]["properties"] == {
        "enabled": {"type": "boolean"},
        "count": {"type": "integer"},
    }
    assert by_name["refund"]["description"] == "Refund an amount."
    assert all(t["type"] == "function" for t in tools)


def test_derive_tools_no_declarations_gives_no_tools():
    assert gen.derive_tools("You are a helpful assistant.") == []


def test_derive_tools_prefers_declared_tools():
    declared = [{"type": "function", "function": {"name": "x", "parameters": {}}}]
    assert gen.derive_tools("- other(a): ignored", declared) == declared


def test_context_round_robin_by_sorted_index():
    artifacts = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
    picks = [gen.context_for(i, artifacts)["id"] for i in range(7)]
    assert picks == ["a", "b", "c", "a", "b", "c", "a"]
