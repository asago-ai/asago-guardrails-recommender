"""Pytest configuration and fixtures."""

import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def recommend_run(tmp_path_factory):
    """Run recommend command once per test module (slow operation)."""
    from asago_guardrails_recommender import recommend

    # Set env vars to use cache instead of real LLM calls
    old_base_url = os.environ.get("LITELLM_BASE_URL")
    old_api_key = os.environ.get("LITELLM_API_KEY")
    try:
        os.environ["LITELLM_BASE_URL"] = "http://unused"
        os.environ["LITELLM_API_KEY"] = "unused"

        run_dir = tmp_path_factory.mktemp("recommend_run")
        recommend.main(
            [
                "--pipeline-results",
                str(REPO_ROOT / "examples/pipeline_results"),
                "--tag-cache",
                str(REPO_ROOT / "examples/tag_cache"),
                "--run-id",
                "t",
                "--out",
                str(run_dir),
            ]
        )
        return run_dir / "t"
    finally:
        # Restore old values
        if old_base_url is not None:
            os.environ["LITELLM_BASE_URL"] = old_base_url
        else:
            os.environ.pop("LITELLM_BASE_URL", None)
        if old_api_key is not None:
            os.environ["LITELLM_API_KEY"] = old_api_key
        else:
            os.environ.pop("LITELLM_API_KEY", None)
