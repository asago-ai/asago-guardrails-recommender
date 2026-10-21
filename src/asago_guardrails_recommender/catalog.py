"""Catalog loader: Parse atomic YAML guardrails into RailCard objects."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import (
    DEFAULT_GUARD_MODEL,
    DETECTOR_TIERS,
    EXTENDED_RAIL_ID,
    INSTANCE_SIGNALS,
    RAIL_YAML_DIR,
    RailCard,
)


def load_catalog(include_extended: bool = True, guard_model: str = DEFAULT_GUARD_MODEL) -> list[RailCard]:
    """Load all atomic YAML rails into RailCard objects."""
    cards: list[RailCard] = []
    yaml_dir = RAIL_YAML_DIR

    if not yaml_dir.exists():
        raise FileNotFoundError(f"RAIL_YAML_DIR does not exist: {yaml_dir}")

    # Parse atomic YAMLs
    for yaml_file in sorted(yaml_dir.glob("*.yaml")):
        try:
            with open(yaml_file) as f:
                raw = yaml.safe_load(f) or {}

            card = _parse_yaml_to_card(yaml_file, raw)
            if card:
                cards.append(card)
        except Exception as e:
            raise ValueError(f"Failed to parse {yaml_file.name}: {e}") from e

    # Add extended rail (Tier-2 self-check)
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

    return cards


def _parse_yaml_to_card(yaml_file: Path, raw: dict[str, Any]) -> RailCard | None:
    """Parse one atomic YAML into a RailCard."""
    card_id = yaml_file.stem

    rails_config = raw.get("rails", {}).get("config", {})
    rails_input = raw.get("rails", {}).get("input", {})
    flows = rails_input.get("flows", [])
    placement = "input" if flows else "unknown"

    # Determine detector type
    if "sensitive_data_detection" in rails_config:
        return _parse_pii_rail(card_id, rails_config["sensitive_data_detection"], placement)
    elif "injection_detection" in rails_config:
        return _parse_injection_rail(card_id, rails_config["injection_detection"], placement)
    elif "hf_classifier" in rails_config:
        return _parse_hf_classifier_rail(card_id, rails_config["hf_classifier"], placement)
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
