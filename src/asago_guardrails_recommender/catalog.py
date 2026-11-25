"""Catalog loader: Parse atomic YAML guardrails into RailCard objects."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

from .models import (
    DEFAULT_GUARD_MODEL,
    DETECTOR_TIERS,
    EXTENDED_RAIL_ID,
    INSTANCE_SIGNALS,
    OUTPUT_JUDGE_RAIL_ID,
    OUTPUT_STAGES_PATH,
    RAIL_YAML_DIR,
    RailCard,
)


def load_catalog(include_extended: bool = True, guard_model: str = DEFAULT_GUARD_MODEL) -> list[RailCard]:
    """Load all atomic YAML rails into RailCard objects."""
    cards: list[RailCard] = []
    yaml_dir = RAIL_YAML_DIR

    if not yaml_dir.exists():
        raise FileNotFoundError(f"RAIL_YAML_DIR does not exist: {yaml_dir}")

    output_stages = _load_output_stages()

    # Parse atomic YAMLs
    for yaml_file in sorted(yaml_dir.glob("*.yaml")):
        try:
            with open(yaml_file) as f:
                raw = yaml.safe_load(f) or {}

            card = _parse_yaml_to_card(yaml_file, raw)
            if card:
                _apply_output_stage(card, raw, output_stages)
                cards.append(card)
        except Exception as e:
            raise ValueError(f"Failed to parse {yaml_file.name}: {e}") from e

    # Add extended rails (Tier-2 self-check)
    if include_extended:
        extended_card = RailCard(
            id=EXTENDED_RAIL_ID,
            type="self_check_input",
            tier=DETECTOR_TIERS["self_check_input"],
            placement="input",
            detects=INSTANCE_SIGNALS[EXTENDED_RAIL_ID],
            tags=["prompt-injection", "jailbreak", "social-engineering"],
            in_default_catalog=False,
            parameters={"guard_model": guard_model},
            source_path=None,
        )
        cards.append(extended_card)

        # Add output judge rail (Tier-2 self-check on output)
        output_judge_card = RailCard(
            id=OUTPUT_JUDGE_RAIL_ID,
            type="self_check_output",
            tier=DETECTOR_TIERS["self_check_input"],  # Same tier as input judge
            placement="output",
            detects=INSTANCE_SIGNALS[OUTPUT_JUDGE_RAIL_ID],
            tags=["social-engineering", "fabricated-evidence", "exfiltration"],
            in_default_catalog=False,
            parameters={"guard_model": guard_model},
            source_path=None,
        )
        cards.append(output_judge_card)

    return cards


def _parse_yaml_to_card(yaml_file: Path, raw: dict[str, Any]) -> RailCard | None:
    """Parse one atomic YAML into a RailCard."""
    card_id = yaml_file.stem

    rails_config = raw.get("rails", {}).get("config", {})
    input_flows = (raw.get("rails", {}).get("input") or {}).get("flows", [])
    output_flows = (raw.get("rails", {}).get("output") or {}).get("flows", [])
    # Placement is the stage the card's own flows run in. Selection may still reuse input cards at output.
    if input_flows and output_flows:
        placement = "both"
    elif output_flows:
        placement = "output"
    elif input_flows:
        placement = "input"
    else:
        placement = "unknown"

    # Determine detector type
    if "sensitive_data_detection" in rails_config:
        return _parse_pii_rail(card_id, rails_config["sensitive_data_detection"], placement)
    elif "injection_detection" in rails_config:
        return _parse_injection_rail(card_id, rails_config["injection_detection"], placement)
    elif "hf_classifier" in rails_config:
        return _parse_hf_classifier_rail(card_id, rails_config["hf_classifier"], placement)
    elif "regex_detection" in rails_config:
        return _parse_regex_rail(card_id, rails_config["regex_detection"], placement)
    else:
        raise ValueError(f"Unknown detector type in {yaml_file.name}")


def _parse_pii_rail(card_id: str, config: dict[str, Any], placement: str) -> RailCard:
    """Parse sensitive_data_detection rail."""
    entities: list[str] = config.get("input", {}).get("entities", [])
    recognizers = config.get("recognizers", [])

    # Build detects list
    detects = [f"pii:{entity}" for entity in entities]

    # Build parameters from recognizers
    parameters: dict[str, Any] = {"entities": entities, "regexes": []}

    for recognizer in recognizers:
        entity = recognizer.get("supported_entity", "")
        patterns = recognizer.get("patterns", [])
        for pattern in patterns:
            parameters["regexes"].append(
                {
                    "entity": entity,
                    "name": pattern.get("name", ""),
                    "regex": pattern.get("regex", ""),
                    "score": pattern.get("score", 1),
                }
            )

    return RailCard(
        id=card_id,
        type="sensitive_data_detection",
        tier=DETECTOR_TIERS["sensitive_data_detection"],
        placement=placement,
        detects=detects,
        parameters=parameters,
        tags=["pii", "personal-information", "personally-identifiable-information"],
        source_path=str(RAIL_YAML_DIR / f"{card_id}.yaml"),
    )


def _parse_injection_rail(card_id: str, config: dict[str, Any], placement: str) -> RailCard:
    """Parse injection_detection rail."""
    injections: list[str] = config.get("injections", [])

    # Map injection types to signals
    injection_signal_map = {
        "code": "code_payload",
        "sqli": "sql_payload",
        "xss": "markup_script",
        "template": "template_expr",
    }

    detects = [injection_signal_map.get(inj, inj) for inj in injections]

    return RailCard(
        id=card_id,
        type="injection_detection",
        tier=DETECTOR_TIERS["injection_detection"],
        placement=placement,
        detects=detects,
        parameters={"injections": injections},
        tags=["prompt-injection", "jailbreak"] if "code" in injections or "sqli" in injections else [],
        source_path=str(RAIL_YAML_DIR / f"{card_id}.yaml"),
    )


def _parse_hf_classifier_rail(card_id: str, config: dict[str, Any], placement: str) -> RailCard:
    """Parse hf_classifier rail."""
    # Extract classifier name (e.g., "prompt-injection" or "guardian-hap")
    classifier_name = ""
    classifier_model = ""
    classifier_threshold = 0.5

    for name, cfg in config.items():
        classifier_name = name
        classifier_model = cfg.get("model", "")
        classifier_threshold = cfg.get("threshold", 0.5)
        break

    # Look up signals from INSTANCE_SIGNALS
    instance_key = f"hf_classifier_{classifier_name}"
    detects = INSTANCE_SIGNALS.get(instance_key, [])

    # Tags
    tags = []
    if "prompt" in classifier_name.lower():
        tags = ["prompt-injection", "jailbreak"]
    elif "wolf" in classifier_name.lower():
        tags = ["prompt-injection", "jailbreak"]
    elif "hap" in classifier_name.lower() or "guardian" in classifier_name.lower():
        tags = ["content-safety", "toxicity", "hate", "profanity"]

    parameters = {
        "classifier": classifier_name,
        "model": classifier_model,
        "threshold": classifier_threshold,
    }

    return RailCard(
        id=card_id,
        type="hf_classifier",
        tier=DETECTOR_TIERS["hf_classifier"],
        placement=placement,
        detects=detects,
        parameters=parameters,
        tags=tags,
        source_path=str(RAIL_YAML_DIR / f"{card_id}.yaml"),
    )


def _parse_regex_rail(card_id: str, config: dict[str, Any], placement: str) -> RailCard:
    """Parse regex_detection rail. Signals come from INSTANCE_SIGNALS (patterns are per card)."""
    patterns: list[str] = []
    for stage in ("input", "output", "retrieval"):
        patterns.extend((config.get(stage) or {}).get("patterns", []))
    if card_id not in INSTANCE_SIGNALS:
        raise ValueError(f"regex rail {card_id} has no INSTANCE_SIGNALS entry")
    return RailCard(
        id=card_id,
        type="regex_detection",
        tier=DETECTOR_TIERS["regex_detection"],
        placement=placement,
        detects=INSTANCE_SIGNALS[card_id],
        parameters={"patterns": patterns},
        tags=["regex", *(sig.replace("_", "-") for sig in INSTANCE_SIGNALS[card_id])],
        source_path=str(RAIL_YAML_DIR / f"{card_id}.yaml"),
    )


def _load_output_stages() -> dict[str, dict[str, str]]:
    """Read output_stages.yaml: detector family -> {config: transform name, flow: output flow}."""
    with open(OUTPUT_STAGES_PATH) as f:
        return yaml.safe_load(f) or {}


def _apply_output_stage(card: RailCard, raw: dict[str, Any], output_stages: dict[str, dict[str, str]]) -> None:
    """Set the card's output_flow and placement for running it on the bot reply.

    A card that defines its own output flow keeps its placement and uses that flow. Otherwise the
    detector family's stage applies and an input card becomes "both".
    """
    own_flows = (raw.get("rails", {}).get("output") or {}).get("flows", [])
    if own_flows:
        if len(own_flows) != 1 or not isinstance(own_flows[0], str):
            raise ValueError(f"{card.id}: expected exactly one string output flow, got {own_flows}")
        card.output_flow = own_flows[0]
        return
    stage = output_stages.get(card.type)
    if stage is None:
        return
    if card.placement == "input":
        card.placement = "both"
    card.output_flow = stage["flow"].replace("{classifier}", str(card.parameters.get("classifier", "")))


def _transform_as_is(family: str, cfg: dict[str, Any]) -> None:
    """Keep the detector config unchanged."""


def _transform_input_to_output(family: str, cfg: dict[str, Any]) -> None:
    """Move the detector's `input` dict to `output` (regex_detection)."""
    rd = cfg[family]
    if "output" not in rd:
        rd["output"] = rd.pop("input", {})
    rd.pop("input", None)


def _transform_input_entities_to_output(family: str, cfg: dict[str, Any]) -> None:
    """sensitive_data_detection: output = {entities: input.entities}; other keys such as recognizers stay."""
    sdd = cfg[family]
    entities = (sdd.pop("input", None) or {}).get("entities", [])
    sdd["output"] = {"entities": entities}


_OUTPUT_TRANSFORMS = {
    "as_is": _transform_as_is,
    "input_to_output": _transform_input_to_output,
    "input_entities_to_output": _transform_input_entities_to_output,
}


def output_stage_config(family: str, rails_config: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a card's rails.config rewritten for the bot reply, per output_stages.yaml.

    Args:
        family: detector family, the card's `type` (e.g. "regex_detection")
        rails_config: the card's `rails.config` mapping, left unmodified
    """
    stage = _load_output_stages().get(family)
    if stage is None:
        raise ValueError(f"no output stage declared for detector family {family!r}")
    if family not in rails_config:
        raise ValueError(f"rails.config has no {family!r} section")
    cfg = copy.deepcopy(rails_config)
    _OUTPUT_TRANSFORMS[stage["config"]](family, cfg)
    return cfg


def cards_by_id(cards: list[RailCard]) -> dict[str, RailCard]:
    """Build id -> RailCard index."""
    return {card.id: card for card in cards}


if __name__ == "__main__":
    cards = load_catalog(include_extended=True)
    by_type = {}
    for card in cards:
        by_type.setdefault(card.type, []).append(card)

    print(f"Total cards: {len(cards)}")
    for typ, cs in sorted(by_type.items()):
        print(f"  {typ}: {len(cs)}")

    # Find PII entities with no regex
    pii_cards = [c for c in cards if c.type == "sensitive_data_detection"]
    print("\nPII entities with no regex:")
    for card in pii_cards:
        entities = card.parameters.get("entities", [])
        regexes = card.parameters.get("regexes", [])
        regex_entities = {r["entity"] for r in regexes}
        missing = [e for e in entities if e not in regex_entities]
        if missing:
            print(f"  {card.id}: {', '.join(missing)}")
