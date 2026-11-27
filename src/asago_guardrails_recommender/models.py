"""Shared contracts for the recommender.

Every component reads and writes these dataclasses; keep field names stable.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

REPO_ROOT = Path(__file__).resolve().parents[2]
CATALOG_DIR = REPO_ROOT / "guardrail-catalog"
RAIL_YAML_DIR = CATALOG_DIR / "rails"
OUTPUT_STAGES_PATH = CATALOG_DIR / "output_stages.yaml"
OUTPUT_DIR = REPO_ROOT / "output"
EFFICACY_DIR = OUTPUT_DIR / "efficacy"
META_DIR = OUTPUT_DIR / "efficacy" / "meta"

DEFAULT_TAGGER_MODEL = "qwen-3.8-27b"
DEFAULT_GUARD_MODEL = "qwen-3.8-27b"
MAX_RAILS_PER_OPTION = 2

Role = Literal["essential", "incidental", "unknown"]
SignalSource = Literal["regex", "heuristic", "llm"]
Status = Literal["recommended", "low_confidence", "gap"]

# Fixed signal vocabulary. "pii:<ENTITY>" signals are generated from the PII rails.
# Signals with no detector in the default catalog are kept on purpose: they drive gap reporting.
SIGNAL_VOCABULARY: dict[str, str] = {
    "instruction_injection": "Text that tries to override, replace or impersonate system/developer instructions "
    "(e.g. 'ignore previous instructions', fake SYSTEM/admin notes, role-play to drop rules).",
    "harmful_language": "Hate, abuse, profanity, threats or other toxic language.",
    "code_payload": "Executable code meant to be run or passed to an interpreter/tool (python, shell, eval/exec).",
    "sql_payload": "SQL statements or SQL injection fragments (SELECT/UNION/DROP, ' OR 1=1, comment tricks).",
    "markup_script": (
        "HTML/JavaScript or markup that could execute in a browser (<script>, event handlers, javascript: URLs)."
    ),
    "template_expr": ("Template-engine expressions ({{ }}, {% %}, ${ }) meant to be evaluated."),
    "social_engineering": (
        "Manipulation of the assistant through pressure, urgency, "
        "false authority or emotional appeal to get it to bypass a rule "
        "or verification step."
    ),
    "fabricated_evidence": (
        "Invented documents, justifications, approvals, records or "
        "credentials presented as genuine to make the assistant act on them."
    ),
    "tool_misuse_request": (
        "Requests steering the assistant to call tools/actions outside "
        "policy or with attacker-chosen parameters (unauthorised payments, "
        "record changes, escalations)."
    ),
    "exfiltration_request": (
        "Attempts to get the assistant to reveal or send data the user is "
        "not entitled to (other users' records, internal data, system prompt)."
    ),
}
PII_SIGNAL_PREFIX = "pii:"

# Detector type -> tier (0 rules | 1 small local model | 2 LLM-judged).
DETECTOR_TIERS: dict[str, int] = {
    "sensitive_data_detection": 0,
    "injection_detection": 0,
    "regex_detection": 0,
    "hf_classifier": 1,
    "self_check_input": 2,
}

# Instance -> signals it detects. The only hand-maintained mapping; PII instances map to "pii:<ENTITY>" in catalog.py.
INSTANCE_SIGNALS: dict[str, list[str]] = {
    "hf_classifier_prompt-injection": ["instruction_injection"],
    "hf_classifier_guardian-hap": ["harmful_language"],
    "hf_classifier_wolf-defender": ["instruction_injection"],
    # Regex rails: patterns written from the signal definitions, not tuned on attacks.
    "regex_instruction_injection": ["instruction_injection"],
    "regex_social_engineering": ["social_engineering"],
    "regex_fabricated_evidence": ["fabricated_evidence"],
    "regex_action_confirmation": ["unauthorized_action"],
    "injection_detector_code": ["code_payload"],
    "injection_detector_sqli": ["sql_payload"],
    "injection_detector_xss": ["markup_script"],
    "injection_detector_template": ["template_expr"],
    "self_check_input_policy": [
        "social_engineering",
        "fabricated_evidence",
        "tool_misuse_request",
        "exfiltration_request",
        "instruction_injection",
    ],
    "self_check_output_policy": [
        "unauthorized_action",
        "fabricated_evidence",
        "social_engineering",
        "exfiltration_request",
        "harmful_language",
    ],
}

EXTENDED_RAIL_ID = "self_check_input_policy"
OUTPUT_JUDGE_RAIL_ID = "self_check_output_policy"
MAX_CONFIG_NAME_LEN = 44

# Mapping of non-PII rail IDs to short, k8s-safe config names
EXPLICIT_CONFIG_NAMES: dict[str, str] = {
    "hf_classifier_prompt-injection": "prompt-injection-detector",
    "hf_classifier_guardian-hap": "hate-speech-detector",
    "hf_classifier_wolf-defender": "wolf-defender-detector",
    "regex_instruction_injection": "regex-injection-detector",
    "regex_social_engineering": "regex-social-eng-detector",
    "regex_fabricated_evidence": "regex-fabricated-detector",
    "regex_action_confirmation": "regex-action-detector",
    "injection_detector_code": "code-injection-detector",
    "injection_detector_sqli": "sql-injection-detector",
    "injection_detector_xss": "xss-detector",
    "injection_detector_template": "template-injection-detector",
    "self_check_input_policy": "llm-policy-judge",
}


def config_name(rail_id: str) -> str:
    """
    Map a rail_id to a short, k8s-safe config name.

    Non-PII rails use explicit mappings.
    PII rails (pii_ENTITY): "pii-" + entity lowercased + "-detector"
      (special case: PERSON -> "pii-name-detector")
    Combined options: keep format as-is but lowercase (e.g., "01-1d16ebb7-opt1")

    All names must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ and be <= MAX_CONFIG_NAME_LEN.
    """
    # Check explicit mapping first
    if rail_id in EXPLICIT_CONFIG_NAMES:
        name = EXPLICIT_CONFIG_NAMES[rail_id]
    # Check for combined option format (e.g., "01-1d16ebb7-opt1")
    elif rail_id.count("-") >= 2 and rail_id[-1].isdigit():
        # Keep as-is but lowercase
        name = rail_id.lower()
    # Check for PII rail
    elif rail_id.startswith("pii_"):
        entity = rail_id[4:]  # Remove "pii_" prefix
        # Special case: PERSON detects names
        if entity == "PERSON":
            name = "pii-name-detector"
        else:
            # Convert entity to lowercase, replace '_' with '-'
            entity_lower = entity.lower().replace("_", "-")
            name = f"pii-{entity_lower}-detector"
    else:
        # Generic fallback: lowercase, non-alphanumeric to "-", collapse, strip
        name = rail_id.lower()
        name = __import__("re").sub(r"[^a-z0-9-]", "-", name)
        name = __import__("re").sub(r"-+", "-", name)
        name = name.strip("-")

    # Validate
    if not __import__("re").match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", name):
        raise ValueError(
            f"Invalid config name format for '{rail_id}': '{name}' (must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$)"
        )
    if len(name) > MAX_CONFIG_NAME_LEN:
        raise ValueError(f"Config name too long for '{rail_id}': '{name}' ({len(name)} > {MAX_CONFIG_NAME_LEN})")

    return name


@dataclass
class RailCard:
    id: str
    type: str
    tier: int
    placement: str
    detects: list[str]
    parameters: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    in_default_catalog: bool = True
    source_path: str | None = None
    output_flow: str | None = None  # flow that runs the card on the bot reply (from output_stages.yaml)


@dataclass
class AttackRecord:
    attack_id: str
    short_id: str
    use_case: str
    artifact_path: str
    scenario_path: str | None
    adversarial_text: str
    messages: list[dict[str, Any]]  # chat messages up to and including the attack turn
    attack_turn_index: int
    injection_surface: str
    narrative_summary: str
    threat_id: str | None = None
    mechanism: str | None = None
    owasp_ids: list[str] = field(default_factory=list)
    atlas_ids: list[str] = field(default_factory=list)
    laaf_ids: list[str] = field(default_factory=list)
    baseline_outcome: str | None = None
    detector_rubric: dict[str, Any] | None = None


@dataclass
class Signal:
    signal: str
    role: Role = "unknown"
    source: SignalSource = "heuristic"
    evidence: str = ""


@dataclass
class Candidate:
    attack_id: str
    rail_id: str
    evidence: Literal["core", "incidental"]
    confirmed: bool = False
    matched_signals: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass
class Option:
    rank: int
    rails: list[str]
    evidence: str
    cost_tier: int
    covers_signals: list[str]
    rationale: str
    config_dir: str | None = None
    test_plan: list[dict] = field(default_factory=list)
    output_rails: list[str] = field(default_factory=list)
    config_id: str | None = None  # Actual config_id (includes "-out" suffix if output rails present)


@dataclass
class Recommendation:
    attack_id: str
    short_id: str
    use_case: str
    signals: list[Signal]
    options: list[Option]
    status: Status
    missing_signals: list[str] = field(default_factory=list)
    tested: bool = False
    untested_reason: str | None = None


@dataclass
class EfficacyRecord:
    run_id: str
    catalog_version: str
    attack_id: str
    use_case: str
    attack_features: dict[str, Any]
    rails: list[str]
    option_rank: int | None
    level: Literal["detection", "end_to_end", "with_output"]
    status: str  # passed | modified | blocked | error
    blocking_rail: str | None
    judge_outcome: str | None
    latency_ms: float | None
    timestamp: str
    error: str | None = None
    test_label: str | None = None
    probe_messages: list[dict] = field(default_factory=list)
    # Output rails fields (optional)
    output_status: str | None = None  # passed | modified | blocked | error
    output_blocking_rail: str | None = None
    output_latency_ms: float | None = None
    output_error: str | None = None
    model_reply: str | None = None
    attack_success: bool | None = None  # True | False | None (unparseable)
    success_reason: str | None = None
    outcome: str | None = None  # blocked_input | blocked_output | attack_succeeded | model_refused | unknown | error
    output_would_block: bool | None = None


def to_dict(obj: Any) -> Any:
    """Dataclass (or list of them) -> JSON-ready structure.

    For Option objects, omit output_rails if it's empty and config_id if it's None to maintain backward compatibility.
    For AttackRecord, omit detector_rubric to maintain backward compatibility with run1.
    """
    if isinstance(obj, list):
        return [to_dict(o) for o in obj]

    if isinstance(obj, Option):
        # Handle Option specially to omit empty output_rails and None config_id
        d = asdict(obj)
        if not d.get("output_rails"):
            d.pop("output_rails", None)
        if d.get("config_id") is None:
            d.pop("config_id", None)
        return d

    if isinstance(obj, AttackRecord):
        # Omit detector_rubric to keep run1 byte-identical
        d = asdict(obj)
        d.pop("detector_rubric", None)
        return d

    if isinstance(obj, Recommendation):
        # Handle Recommendation to process options properly
        d = asdict(obj)
        if "options" in d and isinstance(d["options"], list):
            d["options"] = [to_dict(opt) for opt in obj.options]
        return d

    return asdict(obj)
