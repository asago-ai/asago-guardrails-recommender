"""Signal extraction and LLM tagging: Extract and enrich signals."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path

import requests

from .models import (
    DEFAULT_TAGGER_MODEL,
    REPO_ROOT,
    SIGNAL_VOCABULARY,
    AttackRecord,
    RailCard,
    Signal,
)

# Track regex compile failures
_REGEX_FAILURES: list[tuple[str, str]] = []


def extract_deterministic(attack: AttackRecord, cards: list[RailCard]) -> list[Signal]:
    """Extract deterministic signals from attack.adversarial_text."""
    text = attack.adversarial_text
    signals: list[Signal] = []

    if not text:
        return signals

    # (a) PII signals from regex
    seen_pii_entities: set[str] = set()
    pii_cards = [c for c in cards if c.type == "sensitive_data_detection"]

    for card in pii_cards:
        regexes = card.parameters.get("regexes", [])
        for regex_item in regexes:
            entity = regex_item.get("entity", "")
            regex_str = regex_item.get("regex", "")

            if not entity or entity in seen_pii_entities:
                continue

            try:
                pattern = re.compile(regex_str)
                match = pattern.search(text)
                if match:
                    evidence = match.group(0)[:80]
                    signals.append(
                        Signal(
                            signal=f"pii:{entity}",
                            role="unknown",
                            source="regex",
                            evidence=evidence,
                        )
                    )
                    seen_pii_entities.add(entity)
            except re.error as e:
                _REGEX_FAILURES.append((entity, str(e)))
                continue

    # (b) Heuristic signals (one per type, with first match as evidence)
    heuristic_signals: dict[str, tuple[str, str]] = {}  # signal -> (evidence, pattern)

    # SQL payload
    if not _has_signal(signals, "sql_payload"):
        # Require statement structure; bare keywords ("update", "from", "where") are ordinary English.
        sql_patterns = [
            (r"\bSELECT\b[^.?!\n]{1,120}?\bFROM\b\s+\w+", "SQL select"),
            (r"\bINSERT\s+INTO\s+\w+", "SQL insert"),
            (r"\bUPDATE\s+\w+\s+SET\s+\w+\s*=", "SQL update"),
            (r"\bDELETE\s+FROM\s+\w+", "SQL delete"),
            (r"\b(DROP|ALTER|TRUNCATE)\s+TABLE\s+\w+", "SQL DDL"),
            (r"\bUNION\s+(ALL\s+)?SELECT\b", "SQL union"),
            (r"['\"]\s*OR\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+", "SQL tautology"),
            (r"['\"]\s*;\s*--", "SQL comment"),
        ]
        for pattern_str, label in sql_patterns:
            match = re.search(pattern_str, text, re.IGNORECASE)
            if match:
                heuristic_signals["sql_payload"] = (match.group(0)[:80], label)
                break

    # Markup/Script payload
    if not _has_signal(signals, "markup_script"):
        markup_patterns = [
            (r"<script[^>]*>", "<script>"),
            (r"on\w+\s*=", "event handler"),
            (r"javascript:", "javascript: URL"),
            (r"<iframe[^>]*>", "<iframe>"),
            (r"<img[^>]*\s+onerror\s*=", "img onerror"),
        ]
        for pattern_str, label in markup_patterns:
            match = re.search(pattern_str, text, re.IGNORECASE)
            if match:
                heuristic_signals["markup_script"] = (match.group(0)[:80], label)
                break

    # Template expressions
    if not _has_signal(signals, "template_expr"):
        template_patterns = [
            (r"{{", "{{}}"),
            (r"{%", "{%%}"),
            (r"\$\{", "${}"),
        ]
        for pattern_str, label in template_patterns:
            if pattern_str in text:
                heuristic_signals["template_expr"] = (pattern_str, label)
                break

    # Code payload
    if not _has_signal(signals, "code_payload"):
        code_patterns = [
            (r"```(python|bash|sh)", "code fence"),
            (r"\b(eval|exec|os\.system|subprocess|import os|__import__)\b", "exec function"),
            (r"rm\s+-rf|curl\s+.*\|\s*sh", "dangerous command"),
        ]
        for pattern_str, label in code_patterns:
            match = re.search(pattern_str, text, re.IGNORECASE)
            if match:
                heuristic_signals["code_payload"] = (match.group(0)[:80], label)
                break

    # Convert heuristic signals to Signal objects
    for signal_name, (evidence, _) in heuristic_signals.items():
        signals.append(
            Signal(
                signal=signal_name,
                role="unknown",
                source="heuristic",
                evidence=evidence,
            )
        )

    return signals


def _has_signal(signals: list[Signal], signal_name: str) -> bool:
    """Check if a signal name is already in the list."""
    return any(s.signal == signal_name for s in signals)


def tag_attack(
    attack: AttackRecord,
    deterministic: list[Signal],
    model: str = DEFAULT_TAGGER_MODEL,
    cache_dir: Path | None = None,
    base_url: str | None = None,
    disable_thinking: bool = True,
) -> list[Signal]:
    """Enrich deterministic signals with LLM labels."""
    cache_file = None
    if cache_dir:
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"{_hash_attack_id(attack.attack_id)}.json"

        if cache_file.exists():
            with open(cache_file) as f:
                cached = json.load(f)
            return _build_signals_from_cached(deterministic, cached)

    if base_url is None:
        base_url = os.getenv("LITELLM_BASE_URL")
    if not base_url:
        raise ValueError("LLM tagger requires --llm-base-url or env LITELLM_BASE_URL")

    try:
        llm_result = _call_tagger_llm(attack, deterministic, model, base_url, disable_thinking)
    except Exception as e:
        # LLM call failed; return deterministic signals with role "unknown" and mark warning
        print(f"Warning: tagger LLM call failed for {attack.attack_id}: {e}")
        for sig in deterministic:
            sig.role = "unknown"
        return deterministic

    # If JSON parse failed, llm_result is None; return deterministic with "unknown" roles
    if llm_result is None:
        for sig in deterministic:
            sig.role = "unknown"
        return deterministic

    # Cache result
    if cache_file:
        with open(cache_file, "w") as f:
            json.dump(llm_result, f)

    # Merge: deterministic signals keep source but take LLM's role; LLM-only signals get source "llm"
    return _merge_signals(deterministic, llm_result)


def _hash_attack_id(attack_id: str) -> str:
    """Hash attack_id to a short filename."""
    return hashlib.sha256(attack_id.encode()).hexdigest()[:16]


def _call_tagger_llm(
    attack: AttackRecord,
    deterministic: list[Signal],
    model: str,
    base_url: str,
    disable_thinking: bool = True,
) -> dict | None:
    """Call the LLM tagger and parse the response."""
    api_key = _get_api_key()
    if not api_key:
        raise ValueError("No API key found (LITELLM_API_KEY, OPENAI_API_KEY, or config.yaml)")

    # Build the prompt
    vocab_str = "\n".join(f"- {name}: {defn}" for name, defn in SIGNAL_VOCABULARY.items())

    deterministic_str = "\n".join(f"- {sig.signal} ({sig.source}): {sig.evidence}" for sig in deterministic)

    prompt = (
        "You are analyzing an attack on an AI system. Your task is to "
        "identify which signals are present in the adversarial text.\n\n"
        "SIGNAL VOCABULARY (definitions):\n"
        f"{vocab_str}\n\n"
        "ATTACK CONTEXT:\n"
        f"- Narrative: {attack.narrative_summary}\n"
        f"- Threat/Mechanism: {attack.threat_id or 'unknown'} / "
        f"{attack.mechanism or 'unknown'}\n\n"
        "ADVERSARIAL TEXT:\n"
        f"{attack.adversarial_text}\n\n"
        "SIGNALS ALREADY DETECTED DETERMINISTICALLY:\n"
        f"{deterministic_str}\n\n"
        "YOUR TASK:\n"
        "(a) List every signal from the vocabulary that you find in the "
        "adversarial text. For each, specify:\n"
        "    - The signal name\n"
        '    - The role: "essential" (the attack\'s payload; removing it '
        'would defeat the attack) or "incidental" (present but not the '
        "point)\n"
        "    - A short evidence quote (≤120 chars)\n\n"
        "(b) For each deterministically-detected signal provided above, "
        "assign it a role (essential or incidental).\n\n"
        "(c) Do NOT include signals outside the vocabulary, except for "
        "specific PII entity names (pii:*).\n\n"
        "RESPOND ONLY WITH JSON, no explanation:\n"
        '{{"signals": [{{"signal": "...", "role": "essential|incidental", '
        '"evidence": "..."}}]}}'
    )

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 4096,
    }
    if disable_thinking:
        payload["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}

    try:
        response = requests.post(
            f"{base_url}/chat/completions",
            json=payload,
            headers=headers,
            timeout=180,
        )
        response.raise_for_status()
        data = response.json()

        # Handle content=None or missing
        content = data.get("choices", [{}])[0].get("message", {}).get("content")
        if not content:
            print(f"Warning: Empty response from LLM for {attack.attack_id}")
            return None

        # Strip <think>...</think> if present (Qwen)
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

        # Strip ``` code fences if present
        content = re.sub(r"```[a-z]*\n?(.*?)\n?```", r"\1", content, flags=re.DOTALL).strip()

        # Extract JSON
        result = _extract_json(content)

        if not result:
            print(f"Warning: Failed to parse tagger response for {attack.attack_id}")
            return None

        return result

    except requests.RequestException as e:
        raise RuntimeError(f"LLM API call failed: {e}") from e


def _extract_json(text: str) -> dict | None:
    """Extract first JSON object from text, finding outermost braces."""
    # Find the outermost { and } by counting braces
    start_idx = text.find("{")
    if start_idx == -1:
        return None

    depth = 0
    end_idx = -1
    for i in range(start_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                end_idx = i
                break

    if end_idx == -1:
        return None

    try:
        json_str = text[start_idx : end_idx + 1]
        return json.loads(json_str)
    except json.JSONDecodeError:
        return None


def _get_api_key() -> str | None:
    """Get API key from environment or config file."""
    # Try environment variables
    key = os.environ.get("LITELLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if key:
        return key

    # Try config file
    config_path = REPO_ROOT / "pipeline_automation" / "config.yaml"
    if config_path.exists():
        import yaml

        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
        key = (
            config.get("api_key")
            or (config.get("llm") or {}).get("api_key")
            or (config.get("litellm") or {}).get("api_key")
        )
        if key:
            return key

    return None


def _build_signals_from_cached(deterministic: list[Signal], cached: dict) -> list[Signal]:
    """Reconstruct signals from cached LLM result."""
    # Build index of cached signals by name
    cached_by_name = {}
    for sig in cached.get("signals", []):
        cached_by_name[sig["signal"]] = sig

    # Merge deterministic signals with cached roles
    result = []
    for det_sig in deterministic:
        if det_sig.signal in cached_by_name:
            cached_sig = cached_by_name[det_sig.signal]
            det_sig.role = cached_sig.get("role", "unknown")
        result.append(det_sig)

    # Add LLM-only signals
    det_names = {sig.signal for sig in deterministic}
    for cached_sig in cached.get("signals", []):
        if cached_sig["signal"] not in det_names:
            result.append(
                Signal(
                    signal=cached_sig["signal"],
                    role=cached_sig.get("role", "unknown"),
                    source="llm",
                    evidence=cached_sig.get("evidence", ""),
                )
            )

    return result


def _merge_signals(deterministic: list[Signal], llm_result: dict) -> list[Signal]:
    """Merge deterministic signals with LLM result."""
    # Build index of LLM signals by name
    llm_by_name = {}
    for sig in llm_result.get("signals", []):
        llm_by_name[sig["signal"]] = sig

    # Merge deterministic signals with LLM roles
    result = []
    for det_sig in deterministic:
        if det_sig.signal in llm_by_name:
            llm_sig = llm_by_name[det_sig.signal]
            det_sig.role = llm_sig.get("role", "unknown")
            if not det_sig.evidence and llm_sig.get("evidence"):
                det_sig.evidence = llm_sig["evidence"]
        result.append(det_sig)

    # Add LLM-only signals
    det_names = {sig.signal for sig in deterministic}
    for llm_sig in llm_result.get("signals", []):
        if llm_sig["signal"] not in det_names:
            result.append(
                Signal(
                    signal=llm_sig["signal"],
                    role=llm_sig.get("role", "unknown"),
                    source="llm",
                    evidence=llm_sig.get("evidence", ""),
                )
            )

    return result


if __name__ == "__main__":
    # Smoke test: load attacks and cards, extract signals
    from .attacks import load_attacks
    from .catalog import load_catalog

    cards = load_catalog(include_extended=False)
    attacks = load_attacks()

    all_signals: list[Signal] = []
    signal_counts: Counter[str] = Counter()

    for attack in attacks:
        signals = extract_deterministic(attack, cards)
        all_signals.extend(signals)
        for sig in signals:
            signal_counts[sig.signal] += 1

    print(f"Total signals extracted: {len(all_signals)}")
    print("\nSignal counts:")
    for sig_name, count in signal_counts.most_common():
        print(f"  {sig_name}: {count}")

    print(f"\nRegex compile failures: {len(_REGEX_FAILURES)}")
    for entity, error in _REGEX_FAILURES[:5]:
        print(f"  {entity}: {error[:60]}")

    # Print 3 example evidences for each signal type
    print("\nExample evidences:")
    sig_examples: dict[str, list[str]] = {}
    for sig in all_signals:
        if sig.signal not in sig_examples:
            sig_examples[sig.signal] = []
        if len(sig_examples[sig.signal]) < 3 and sig.evidence:
            sig_examples[sig.signal].append(sig.evidence[:60])

    for sig_name in sorted(sig_examples.keys()):
        print(f"  {sig_name}:")
        for evidence in sig_examples[sig_name]:
            print(f"    - {evidence}")
