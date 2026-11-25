import asyncio
import json
import logging
from typing import Any, Optional

from nemoguardrails.actions import action
from nemoguardrails.actions.rail_outcome import RailOutcome
from nemoguardrails.http import HTTPClient
from torch import AcceleratorError

log = logging.getLogger(__name__)

_CLASSIFIERS: dict[str, Any] = {}
_SPECIAL_TOKEN_KEYS = ("bos_token", "eos_token", "unk_token", "sep_token", "pad_token", "cls_token", "mask_token")


def _fallback_pipeline(model_id: str) -> Any:
    """Build the classifier from tokenizer.json, for repos whose tokenizer_config.json
    names a tokenizer class this transformers version does not have (e.g. TokenizersBackend).
    Only the standard special tokens are taken from tokenizer_config.json; the list-valued
    extra_special_tokens entry is ignored."""
    from huggingface_hub import hf_hub_download
    from transformers import AutoModelForSequenceClassification, PreTrainedTokenizerFast, pipeline

    with open(hf_hub_download(model_id, "tokenizer_config.json")) as f:
        tc = json.load(f)
    special = {}
    for key in _SPECIAL_TOKEN_KEYS:
        value = tc.get(key)
        if isinstance(value, dict):
            value = value.get("content")
        if value:
            special[key] = value
    tokenizer = PreTrainedTokenizerFast(tokenizer_file=hf_hub_download(model_id, "tokenizer.json"), **special)
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    return pipeline("text-classification", model=model, tokenizer=tokenizer, truncation=True, top_k=None)


def _load_classifier(model_id: str) -> Any:
    """Return a cached text-classification pipeline for model_id.

    top_k=None returns every label's score (the pipeline default returns only the top label),
    so the blocked_labels/threshold check sees the full distribution."""
    if model_id in _CLASSIFIERS:
        return _CLASSIFIERS[model_id]
    from transformers import pipeline

    try:
        clf = pipeline("text-classification", model=model_id, truncation=True, top_k=None)
        path = "pipeline"
    except (ValueError, OSError) as e:
        if "tokenizer" not in str(e).lower():
            raise
        log.warning("HF classifier '%s': pipeline() failed (%s); using tokenizer.json fallback", model_id, e)
        clf = _fallback_pipeline(model_id)
        path = "fallback"
    log.info("HF classifier '%s' loaded via %s path", model_id, path)
    _CLASSIFIERS[model_id] = clf
    return clf


def _classifier_settings(config: Any | None, name: str) -> tuple[str, float, set[str]]:
    """Read model, threshold and blocked_labels for `name` from rails.config.hf_classifier,
    the same section NeMo's hf_classifier actions read."""
    classifiers = getattr(config.rails.config, "hf_classifier", None) if config else None
    if not classifiers:
        raise ValueError("hf_classifier action called but no 'hf_classifier' section found in rails.config.")
    cfg = classifiers.get(name)
    if cfg is None:
        raise ValueError(f"Unknown classifier '{name}'. Available: {list(classifiers)}")
    if isinstance(cfg, dict):
        model, threshold, blocked = cfg.get("model"), cfg.get("threshold"), cfg.get("blocked_labels")
    else:
        model = getattr(cfg, "model", None)
        threshold = getattr(cfg, "threshold", None)
        blocked = getattr(cfg, "blocked_labels", None)
    if not model:
        raise ValueError(f"hf_classifier '{name}' has no model.")
    return model, float(threshold), set(blocked or [])


def _scores(raw: Any) -> list[tuple[str, float]]:
    if raw and isinstance(raw[0], list):
        raw = raw[0]
    return [(item["label"], float(item["score"])) for item in raw]


async def _windowed_allowed(classifier: str, config: Any | None, text: str, window_size: int, overlap: int) -> bool:
    """Classify every window of text. Returns False if any window has a blocked label
    with score >= threshold."""
    if not text:
        return True
    model_id, threshold, blocked = _classifier_settings(config, classifier)
    loop = asyncio.get_running_loop()
    clf = await loop.run_in_executor(None, _load_classifier, model_id)

    retries = 0
    while True:
        try:
            for i, window in enumerate(_sliding_windows(text, window_size, overlap)):
                raw = await loop.run_in_executor(None, clf, window)
                triggered = [(lbl, s) for lbl, s in _scores(raw) if lbl in blocked and s >= threshold]
                if triggered:
                    log.info("HF classifier '%s': blocked window %d (detections: %s)", classifier, i, triggered)
                    return False
            return True
        except AcceleratorError as e:
            if retries >= 3:
                raise e
            window_size = window_size // 2
            overlap = overlap // 2
            retries += 1


def _sliding_windows(text: str, window_size: int, overlap: int) -> list[str]:
    if len(text) <= window_size:
        return [text]
    windows = []
    step = window_size - overlap
    start = 0
    while start < len(text):
        windows.append(text[start : start + window_size])
        if start + window_size >= len(text):
            break
        start += step
    return windows


@action()
async def hf_classifier_check_input_windowed(
    classifier: str,
    config: Any | None = None,
    context: Optional[dict] = None,
    text: Optional[str] = None,
    http_client: HTTPClient | None = None,
    window_size: int = 2500,
    overlap: int = 500,
    **kwargs,
) -> RailOutcome:
    if text is None:
        text = (context.get("user_message") or "") if context else ""
    allowed = await _windowed_allowed(classifier, config, text, window_size, overlap)
    return RailOutcome.allow() if allowed else RailOutcome.block()


@action()
async def hf_classifier_check_output_windowed(
    classifier: str,
    config: Any | None = None,
    context: Optional[dict] = None,
    text: Optional[str] = None,
    http_client: HTTPClient | None = None,
    model_name: Optional[str] = None,
    window_size: int = 2500,
    overlap: int = 500,
    **kwargs,
) -> RailOutcome:
    # Streaming output rail path doesn't resolve flow variables (see NeMo's hf_classifier_check_output).
    if classifier.startswith("$") and model_name:
        classifier = model_name
    if text is None:
        text = (context.get("bot_message") or "") if context else ""
    allowed = await _windowed_allowed(classifier, config, text, window_size, overlap)
    return RailOutcome.allow() if allowed else RailOutcome.block()
