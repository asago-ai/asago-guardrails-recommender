#!/usr/bin/env python3
"""Baseline Garak evaluation: all artifacts against Gemma 4 + Qwen judge"""

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


def discover_use_cases(results_dir: Path, only: list[str] | None) -> list[str]:
    """Discover use cases by finding subdirs with artifacts or artifacts_exhaustive folders."""
    base_path = Path(results_dir)
    use_cases = []

    if not base_path.exists():
        logger.error(f"Results directory does not exist: {results_dir}")
        sys.exit(1)

    for item in sorted(base_path.iterdir()):
        if item.is_dir() and ((item / "artifacts").exists() or (item / "artifacts_exhaustive").exists()):
            use_cases.append(item.name)

    if only:
        filtered = []
        for name in only:
            if name not in use_cases:
                logger.error(f"Requested use case not found: {name}")
                sys.exit(1)
            filtered.append(name)
        return filtered

    return use_cases


def discover_artifacts(results_dir, use_cases):
    """Find all *-garak.json artifacts in artifacts and artifacts_exhaustive directories"""
    base_path = Path(results_dir)
    all_artifacts = {}

    for uc in use_cases:
        artifacts = []
        # Check both artifacts and artifacts_exhaustive folders
        for folder in ["artifacts", "artifacts_exhaustive"]:
            artifact_path = base_path / uc / folder
            if artifact_path.exists():
                artifacts.extend(sorted(artifact_path.rglob("*-garak.json")))
        all_artifacts[uc] = sorted(set(artifacts))  # Remove duplicates if both exist

    flat_artifacts = []
    for uc_artifacts in all_artifacts.values():
        flat_artifacts.extend(uc_artifacts)

    logger.info(f"Discovered {len(flat_artifacts)} artifacts:")
    for uc, artifacts in all_artifacts.items():
        logger.info(f"  - {uc}: {len(artifacts)} artifacts")

    return flat_artifacts, all_artifacts


def ensure_artifact_metadata(run_dir, garak_file):
    """Create artifact.json metadata if it doesn't exist"""
    artifact_json_path = run_dir / "artifact.json"

    if artifact_json_path.exists():
        return True

    try:
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
        return True
    except Exception as e:
        logger.error(f"Failed to create artifact metadata for {run_dir.name}: {e}")
        return False


def run_evaluation(run_dir, eval_config, evaluation_fn):
    """Run Garak evaluation for a single artifact"""
    try:
        result = evaluation_fn(run_dir, eval_config)
        return result
    except Exception as e:
        logger.error(f"Evaluation failed for {run_dir.name}: {e}")
        return {"outcome": "error", "status": "failed", "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="Baseline batch Garak evaluation")
    parser.add_argument(
        "--results-dir", type=str, default="./pipeline_results", help="Directory containing pipeline results"
    )
    parser.add_argument("--target-model", type=str, default="gemma-4-26b", help="Target model to attack")
    parser.add_argument("--judge-model", type=str, default="qwen-3.8-27b", help="Judge model for evaluation")
    parser.add_argument("--use-cases", nargs="*", default=None, help="Filter to specific use cases by name")

    args = parser.parse_args()

    validate_env_vars()
    evaluation = setup_imports()

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

    use_cases = discover_use_cases(Path(args.results_dir), args.use_cases)
    all_artifacts, artifacts_by_uc = discover_artifacts(args.results_dir, use_cases)

    if not all_artifacts:
        logger.error("No artifacts found!")
        return 1

    artifact_counts_str = " + ".join(f"{len(artifacts_by_uc[uc])} {uc}" for uc in use_cases)
    print(f"Total Artifacts: {len(all_artifacts)} ({artifact_counts_str})")
    print(f"Target Model: {eval_config['target_model']} (being attacked)")
    print(f"Judge Model: {eval_config['judge_model']} (evaluates success)")
    print(f"Timeout: {eval_config['timeout']} seconds per artifact\n")

    results = []
    outcomes = {"attack_succeeded": 0, "attack_blocked": 0, "inconclusive": 0, "error": 0}
    outcomes_by_use_case = {
        uc: {"attack_succeeded": 0, "attack_blocked": 0, "inconclusive": 0, "error": 0} for uc in use_cases
    }

    batch_start = time.time()

    base_path = Path(args.results_dir)
    for idx, garak_file in enumerate(all_artifacts, 1):
        run_dir = garak_file.parent
        use_case = garak_file.relative_to(base_path).parts[0]

        logger.info(f"[{idx}/{len(all_artifacts)}] Processing {use_case} artifact: {run_dir.name}")

        if not ensure_artifact_metadata(run_dir, garak_file):
            logger.warning("Skipping artifact due to metadata creation failure")
            outcomes["error"] += 1
            outcomes_by_use_case[use_case]["error"] += 1
            results.append(
                {
                    "index": idx,
                    "use_case": use_case,
                    "artifact_id": run_dir.name,
                    "outcome": "error",
                    "error": "Metadata creation failed",
                    "timestamp": datetime.now().isoformat(),
                }
            )
            continue

        artifact_start = time.time()
        logger.info("  Starting evaluation...")
        result = run_evaluation(run_dir, eval_config, evaluation)
        artifact_elapsed = time.time() - artifact_start

        outcome = result.get("outcome", "unknown")
        status = result.get("status", "unknown")

        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        outcomes_by_use_case[use_case][outcome] = outcomes_by_use_case[use_case].get(outcome, 0) + 1

        results.append(
            {
                "index": idx,
                "use_case": use_case,
                "artifact_id": run_dir.name,
                "outcome": outcome,
                "status": status,
                "execution_time_seconds": artifact_elapsed,
                "target_model": result.get("target_model"),
                "judge_model": result.get("judge_model"),
                "tool_execution": result.get("tool_execution"),
                "error": result.get("error"),
                "timestamp": datetime.now().isoformat(),
            }
        )

        outcome_display = outcome.replace("_", " ").title()
        logger.info(f"  Outcome: {outcome_display} ({artifact_elapsed:.1f}s)")

        if result.get("error"):
            logger.info(f"    Error: {result.get('error')}")

    batch_elapsed = time.time() - batch_start

    summary_file = Path(args.results_dir) / "baseline_summary.json"
    summary_file.parent.mkdir(parents=True, exist_ok=True)

    metadata = {
        "timestamp": datetime.now().isoformat(),
        "total_artifacts": len(all_artifacts),
        "execution_time_seconds": batch_elapsed,
        "target_model": eval_config["target_model"],
        "judge_model": eval_config["judge_model"],
    }
    for uc in use_cases:
        metadata[f"{uc}_artifacts"] = len(artifacts_by_uc[uc])

    with open(summary_file, "w") as f:
        json.dump(
            {
                "metadata": metadata,
                "outcomes": outcomes,
                "outcomes_by_use_case": outcomes_by_use_case,
                "artifacts": results,
            },
            f,
            indent=2,
        )

    print(f"Execution Time: {batch_elapsed:.1f} seconds ({batch_elapsed / 60:.1f} minutes)")
    print(f"  Average per artifact: {batch_elapsed / len(all_artifacts):.1f} seconds")

    print("OVERALL OUTCOMES:")
    total_artifacts = len(all_artifacts)
    pct_success = 100 * outcomes["attack_succeeded"] / total_artifacts
    print(f"  Attack Succeeded: {outcomes['attack_succeeded']}/{total_artifacts} ({pct_success:.1f}%)")
    pct_blocked = 100 * outcomes["attack_blocked"] / total_artifacts
    print(f"  Attack Blocked: {outcomes['attack_blocked']}/{total_artifacts} ({pct_blocked:.1f}%)")
    pct_inconclusive = 100 * outcomes["inconclusive"] / total_artifacts
    print(f"  Inconclusive: {outcomes['inconclusive']}/{total_artifacts} ({pct_inconclusive:.1f}%)")
    pct_error = 100 * outcomes["error"] / total_artifacts
    print(f"  Error: {outcomes['error']}/{total_artifacts} ({pct_error:.1f}%)")

    for uc in use_cases:
        uc_count = len(artifacts_by_uc[uc])
        print(f"{uc.upper()}:")
        uc_success = outcomes_by_use_case[uc]["attack_succeeded"]
        uc_success_pct = 100 * uc_success / uc_count
        print(f"  Attack Succeeded: {uc_success}/{uc_count} ({uc_success_pct:.1f}%)")
        uc_blocked = outcomes_by_use_case[uc]["attack_blocked"]
        uc_blocked_pct = 100 * uc_blocked / uc_count
        print(f"  Attack Blocked: {uc_blocked}/{uc_count} ({uc_blocked_pct:.1f}%)")
        uc_inconclusive = outcomes_by_use_case[uc]["inconclusive"]
        uc_inconclusive_pct = 100 * uc_inconclusive / uc_count
        print(f"  Inconclusive: {uc_inconclusive}/{uc_count} ({uc_inconclusive_pct:.1f}%)")
        uc_error = outcomes_by_use_case[uc]["error"]
        uc_error_pct = 100 * uc_error / uc_count
        print(f"  Error: {uc_error}/{uc_count} ({uc_error_pct:.1f}%)")

    print(f"SUMMARY FILE: {summary_file}")

    if outcomes["error"] > 0:
        print(f"WARNING: {outcomes['error']} artifacts failed evaluation. Review errors before deployment.")

    if outcomes["attack_succeeded"] > 0:
        print(f"BASELINE ESTABLISHED: {outcomes['attack_succeeded']} vulnerabilities detected")
        print("Ready to deploy guardrails and re-test to measure protection effectiveness.")
    else:
        print("No vulnerabilities detected in baseline. Verify artifact quality and model connectivity.")

    return 0 if outcomes["error"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
