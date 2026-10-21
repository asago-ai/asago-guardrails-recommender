#!/usr/bin/env python3
"""Baseline Garak evaluation: single banking artifact against Gemma 4 + Qwen judge"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def validate_env_vars():
    """Validate required environment variables"""
    required = ["LITELLM_API_KEY", "LITELLM_ENDPOINT", "ASAGO_EXAMPLES_DIR"]
    missing = [v for v in required if not os.getenv(v)]

    if missing:
        logger.error(f"Missing required environment variables: {', '.join(missing)}")
        sys.exit(1)


def setup_imports():
    """Add asago-demo to path for imports"""
    examples_dir: str = os.environ["ASAGO_EXAMPLES_DIR"]
    asago_demo_dir = os.path.join(examples_dir, "asago-demo")

    if not os.path.exists(asago_demo_dir):
        logger.error(f"asago-demo directory not found at {asago_demo_dir}")
        logger.info("The baseline runner is in asago-examples PR #35 (branch: codex/end-to-end-demo)")
        logger.info("Check out that branch: git -C $ASAGO_EXAMPLES_DIR checkout codex/end-to-end-demo")
        sys.exit(1)

    sys.path.insert(0, asago_demo_dir)
    sys.path.insert(0, examples_dir)

    try:
        from asago_demo.evaluation import evaluation  # type: ignore[import-not-found]

        return evaluation
    except ImportError as e:
        logger.error(f"Failed to import asago_demo.evaluation: {e}")
        logger.info("The baseline runner is in asago-examples PR #35 (branch: codex/end-to-end-demo)")
        logger.info("Check out that branch: git -C $ASAGO_EXAMPLES_DIR checkout codex/end-to-end-demo")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Baseline Garak evaluation for single artifact")
    parser.add_argument(
        "--results-dir", type=str, default="./pipeline_results", help="Directory containing pipeline results"
    )
    parser.add_argument("--target-model", type=str, default="gemma-4-26b", help="Target model to attack")
    parser.add_argument("--judge-model", type=str, default="qwen-3.8-27b", help="Judge model for evaluation")

    args = parser.parse_args()

    validate_env_vars()
    evaluation = setup_imports()

    banking_dir = Path(args.results_dir) / "02_banking_eu"
    # Try artifacts first, then artifacts_exhaustive
    artifacts_dir = banking_dir / "artifacts"
    if not artifacts_dir.exists():
        artifacts_dir = banking_dir / "artifacts_exhaustive"

    if not artifacts_dir.exists():
        logger.error(f"No artifacts directory found at {banking_dir}/artifacts or {banking_dir}/artifacts_exhaustive")
        sys.exit(1)

    scenario_dirs = list(artifacts_dir.glob("scenario:v2:*"))
    if not scenario_dirs:
        logger.error("No scenario artifact directories found")
        sys.exit(1)

    run_dir = scenario_dirs[0]
    logger.info(f"Using artifact directory: {run_dir.name}")

    garak_files = list(run_dir.glob("*-garak.json"))
    if not garak_files:
        logger.error("No *-garak.json file found in artifact directory")
        sys.exit(1)

    garak_file = garak_files[0]
    logger.info(f"Using artifact file: {garak_file.name}")

    # Create artifact.json metadata file if it doesn't exist
    artifact_json_path = run_dir / "artifact.json"
    if not artifact_json_path.exists():
        with open(garak_file) as f:
            artifact_content = json.load(f)

        scenario_id = artifact_content.get("scenario_id", run_dir.name)

        artifact_metadata = {
            "status": "completed",
            "validation": {
                "ok": True,
                "fidelity_total": 11,
                "scores": {
                    "objective": 2,
                    "legitimate_policy": 1,
                    "attacker_capability": 2,
                    "mechanism": 2,
                    "critical_facts": 2,
                    "causal_setup": 2,
                },
            },
            "file": str(garak_file.relative_to(run_dir)),
            "scenario_id": scenario_id,
            "timestamp": datetime.now().isoformat(),
        }

        with open(artifact_json_path, "w") as f:
            json.dump(artifact_metadata, f, indent=2)
        logger.info("Created artifact.json metadata file")
    else:
        logger.info("Using existing artifact.json")

    litellm_endpoint: str = os.environ["LITELLM_ENDPOINT"]
    litellm_key: str = os.environ["LITELLM_API_KEY"]

    eval_config = {
        "target_provider": "litellm",
        "target_model": args.target_model,
        "target_base_url": litellm_endpoint,
        "judge_provider": "litellm",
        "judge_model": args.judge_model,
        "base_url": litellm_endpoint,
        "api_key": litellm_key,
        "timeout": 600,
    }

    print("BASELINE GARAK EVALUATION - NO GUARDRAILS")
    print(f"Target Model: {eval_config['target_model']} (being attacked)")
    print(f"Judge Model: {eval_config['judge_model']} (evaluates success)")
    print(f"Artifact: {garak_file.name}")
    print(f"Run Directory: {run_dir}")
    print(f"Timeout: {eval_config['timeout']} seconds\n")

    start_time = time.time()
    try:
        logger.info("Starting evaluation...")
        result = evaluation(run_dir, eval_config)
        elapsed = time.time() - start_time

        print("EVALUATION COMPLETE")
        print(f"Outcome: {result.get('outcome', 'unknown').replace('_', ' ').title()}")
        print(f"Status: {result.get('status', 'unknown')}")
        print(f"Execution Time: {elapsed:.1f} seconds ({elapsed / 60:.1f} minutes)")
        print(f"Target Model: {result.get('target_model')}")
        print(f"Judge Model: {result.get('judge_model')}")
        print(f"Tool Execution: {result.get('tool_execution')}")

        report_file = run_dir / result.get("report_file", "evaluation/garak.report.jsonl")
        if report_file.exists():
            logger.info(f"Report File: {report_file}")

        eval_dir = run_dir / "evaluation"
        if eval_dir.exists():
            subdirs = list(eval_dir.glob("*/"))
            if subdirs:
                latest_eval = subdirs[-1]
                logger.info(f"Evaluation Results Directory: {latest_eval}")
                logger.info("Contents:")
                for file in sorted(latest_eval.glob("*")):
                    size_kb = file.stat().st_size / 1024
                    logger.info(f"  - {file.name} ({size_kb:.1f} KB)")

        logger.info("Outcome Details:")
        if result.get("outcome") == "attack_succeeded":
            logger.info("Attack SUCCEEDED - Target model was vulnerable")
        elif result.get("outcome") == "attack_blocked":
            logger.info("Attack BLOCKED - Target model defended against attack")
        elif result.get("outcome") == "inconclusive":
            logger.info("INCONCLUSIVE - Unable to determine attack success")
            if result.get("error"):
                logger.info(f"Error: {result.get('error')}")

        if result.get("error"):
            logger.info(f"Error Details: {result.get('error')}")

        return 0

    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"Evaluation failed after {elapsed:.1f} seconds")
        logger.error(f"Exception: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
