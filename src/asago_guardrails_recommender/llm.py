"""LLM chat interface for model replies and output judgments."""

from __future__ import annotations

import re

import requests

from .tag import _get_api_key, safe_request_error


def chat(
    messages: list[dict],
    model: str,
    base_url: str,
    max_tokens: int = 1024,
    disable_thinking: bool = True,
    timeout: float = 120,
) -> str:
    """
    Call an OpenAI-compatible LLM endpoint and return the assistant's response.

    Args:
        messages: List of message dicts with "role" and "content".
        model: Model name.
        base_url: Base URL of the LLM endpoint (e.g., http://localhost:8000).
        max_tokens: Maximum tokens in the response (default 1024).
        disable_thinking: If True, send extra_body with chat_template_kwargs.enable_thinking=False.
        timeout: Request timeout in seconds (default 120).

    Returns:
        Assistant's response content with any <think>...</think> block stripped.

    Raises:
        RuntimeError: On HTTP error or request failure (message does not include URL or key).
    """
    api_key = _get_api_key()
    if not api_key:
        raise RuntimeError("No API key found (LITELLM_API_KEY, OPENAI_API_KEY, or config.yaml)")

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": max_tokens,
    }
    if disable_thinking:
        payload["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}

    try:
        response = requests.post(
            f"{base_url}/chat/completions",
            json=payload,
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()

        # Extract assistant content
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        if not content:
            raise RuntimeError("Empty response from LLM")

        # Strip <think>...</think> if present (Qwen)
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

        return content

    except requests.RequestException as e:
        raise RuntimeError(f"LLM API call failed: {safe_request_error(e)}") from e
