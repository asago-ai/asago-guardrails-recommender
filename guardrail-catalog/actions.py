from typing import Any, Optional

from nemoguardrails.actions import action
from nemoguardrails.actions.rail_outcome import RailOutcome
from nemoguardrails.http import HTTPClient
from nemoguardrails.library.hf_classifier.actions import (
    hf_classifier_check_input,
    hf_classifier_check_output,
)
from torch import AcceleratorError


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

    retries = 0
    while True:
        try:
            windows = _sliding_windows(text, window_size, overlap)
            for i, window in enumerate(windows):
                result = await hf_classifier_check_input(
                    classifier, config, context, text=window, http_client=http_client, **kwargs
                )
                if result != RailOutcome.allow():
                    return result

            return RailOutcome.allow()
        except AcceleratorError as e:
            if retries >= 3:
                raise e
            window_size = window_size // 2
            overlap = overlap // 2
            retries += 1


@action()
async def hf_classifier_check_output_windowed(
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
        text = (context.get("bot_message") or "") if context else ""

    retries = 0
    while True:
        try:
            windows = _sliding_windows(text, window_size, overlap)
            for i, window in enumerate(windows):
                result = await hf_classifier_check_output(
                    classifier, config, context, text=window, http_client=http_client, **kwargs
                )
                if result != RailOutcome.allow():
                    return result

            return RailOutcome.allow()
        except AcceleratorError as e:
            if retries >= 3:
                raise e
            window_size = window_size // 2
            overlap = overlap // 2
            retries += 1
