#!/usr/bin/env python3
"""ASAGO Pipeline Automation: Policy Mapper -> Scenario Generator -> Artifact Generator"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("pipeline.log"), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


class PipelineRunner:
    """Orchestrates the ASAGO pipeline stages"""

    def __init__(self, config_path: str, results_dir: str):
        self.config = self._load_config(config_path)
        self.base_dir = Path(__file__).parent.parent
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def _load_config(self, config_path: str) -> Dict:
        """Load pipeline configuration from YAML"""
        with open(config_path, "r") as f:
            return yaml.safe_load(f)

    def _setup_env_vars(self) -> Dict[str, str]:
        """Setup environment variables for LLM access"""
        env = os.environ.copy()

        # Validate required environment variables
        if not os.getenv("LITELLM_API_KEY"):
            logger.error("LITELLM_API_KEY environment variable not set")
            sys.exit(1)
        if not os.getenv("LITELLM_ENDPOINT"):
            logger.error("LITELLM_ENDPOINT environment variable not set")
            sys.exit(1)
        if not os.getenv("ASAGO_EXAMPLES_DIR"):
            logger.error("ASAGO_EXAMPLES_DIR environment variable not set")
            sys.exit(1)

        litellm_endpoint: str = os.environ["LITELLM_ENDPOINT"]
        litellm_key: str = os.environ["LITELLM_API_KEY"]
        model = self.config["llm"]["model"]

        # Policy Mapper env vars
        env["POLICY_MAPPER_BASE_URL"] = litellm_endpoint
        env["POLICY_MAPPER_MODEL"] = model
        env["POLICY_MAPPER_API_KEY"] = litellm_key

        # Scenario Generator env vars
        env["ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL"] = litellm_endpoint
        env["ASAGO_SCENARIO_GENERATOR_MODEL_NAME"] = model
        env["ASAGO_SCENARIO_GENERATOR_API_KEY"] = litellm_key
        env["ASAGO_SCENARIO_GENERATOR_TIMEOUT"] = "300"

        # Artifact Generator env vars (OpenAI-compatible format)
        env["OPENAI_BASE_URL"] = litellm_endpoint
        env["OPENAI_API_KEY"] = litellm_key
        env["REDTEAM_MODEL"] = model

        return env

    def run_policy_mapper(self, use_case: Dict, env: Dict) -> Optional[Path]:
        """Stage 1: Run policy mapper to extract risks (or use precomputed extraction)"""
        if not self.config["stages"]["policy_mapper"]["enabled"]:
            logger.info("Policy mapper stage disabled, skipping...")
            return None

        logger.info(f"Stage 1: Policy Mapper for {use_case['id']}")

        # Check if risk_extraction is provided (skip policy mapper)
        if "risk_extraction" in use_case and use_case["risk_extraction"]:
            risk_extraction = os.path.expandvars(use_case["risk_extraction"])
            risk_file = self.base_dir / risk_extraction
            if risk_file.exists():
                logger.info(f"Using precomputed risk extraction: {risk_file}")
                return risk_file
            else:
                logger.error(f"Risk extraction file not found: {risk_file}")
                return None

        # Otherwise run policy mapper
        if "policy_doc" not in use_case or not use_case["policy_doc"]:
            logger.error("Neither policy_doc nor risk_extraction specified for use case")
            return None

        policy_doc = self.base_dir / os.path.expandvars(use_case["policy_doc"])
        output_dir = self.results_dir / use_case["id"] / "policy_mapper"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Nexus directory is required by policy mapper
        nexus_dir = Path(os.environ.get("AI_ATLAS_NEXUS_DIR", ""))
        if not nexus_dir.exists():
            logger.error(f"Nexus directory not found at {nexus_dir}")
            logger.info(
                "Set AI_ATLAS_NEXUS_DIR environment variable or clone: git clone https://github.com/IBM/ai-atlas-nexus"
            )
            return None

        examples_dir = Path(os.environ["ASAGO_EXAMPLES_DIR"])
        policy_mapper_dir = examples_dir / "asago-policy-mapper"
        if not policy_mapper_dir.exists():
            logger.error(f"Policy mapper directory not found at {policy_mapper_dir}")
            logger.info("Please clone asago-examples: git clone https://github.com/asago-ai/asago-examples")
            return None

        cmd = [
            "uv",
            "run",
            "asago-policy-mapper",
            "extract",
            str(policy_doc),
            "-o",
            str(output_dir),
            "--nexus-base-dir",
            str(nexus_dir),
            "--base-url",
            env["POLICY_MAPPER_BASE_URL"],
            "--model",
            env["POLICY_MAPPER_MODEL"],
            "--api-key",
            env["POLICY_MAPPER_API_KEY"],
        ]

        logger.info(f"Running: {' '.join(cmd[:6])}... (env vars set)")

        try:
            result = subprocess.run(
                cmd,
                cwd=policy_mapper_dir,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            logger.info("Policy mapper completed successfully")
            logger.debug(result.stdout)

            risks_file = output_dir / "risk-extraction.json"
            if risks_file.exists():
                return risks_file
            else:
                logger.error("Risk extraction JSON not found")
                return None

        except subprocess.CalledProcessError as e:
            logger.error(f"Policy mapper failed: {e}")
            logger.error(f"STDOUT: {e.stdout}")
            logger.error(f"STDERR: {e.stderr}")
            return None

    def run_scenario_generator(self, use_case: Dict, risks_file: Path, env: Dict) -> Optional[Path]:
        """Stage 2: Generate attack scenarios"""
        if not self.config["stages"]["scenario_generator"]["enabled"]:
            logger.info("Scenario generator stage disabled, skipping...")
            return None

        logger.info(f"Stage 2: Scenario Generator for {use_case['id']}")

        use_case_file = self.base_dir / use_case["use_case_file"]
        output_dir = self.results_dir / use_case["id"] / "scenarios"
        output_dir.mkdir(parents=True, exist_ok=True)

        examples_dir = Path(os.environ["ASAGO_EXAMPLES_DIR"])
        scenario_gen_dir = examples_dir / "asago-scenario-generator"
        if not scenario_gen_dir.exists():
            logger.error(f"Scenario generator directory not found at {scenario_gen_dir}")
            logger.info("Please clone asago-examples: git clone https://github.com/asago-ai/asago-examples")
            return None

        sssom_file = scenario_gen_dir / "inputs" / "mappings" / "risk_to_category.sssom.tsv"

        if not sssom_file.exists():
            logger.error(f"SSSOM mapping not found at {sssom_file}")
            return None

        cmd = [
            "uv",
            "run",
            "asago-scenario-generator",
            "generate",
            "--use-case",
            f"@{use_case_file}",
            "--risk-extraction",
            str(risks_file),
            "--sssom",
            str(sssom_file),
            "--output-dir",
            str(output_dir),
            "--generation-mode",
            "coverage",
            "--max-scenario-techniques",
            "1",
        ]

        logger.info(f"Running: {' '.join(cmd[:4])}... (env vars set)")

        try:
            result = subprocess.run(
                cmd,
                cwd=scenario_gen_dir,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            logger.info("Scenario generator completed successfully")
            logger.debug(result.stdout)

            # Find generated scenarios directory (timestamped)
            scenario_dirs = sorted(output_dir.glob("*"))
            if scenario_dirs:
                latest_run = scenario_dirs[-1]
                scenarios_dir = latest_run / "scenarios"
                if scenarios_dir.exists():
                    scenario_files = list(scenarios_dir.glob("*.yaml"))
                    logger.info(f"Generated {len(scenario_files)} scenarios")
                    return scenarios_dir

            logger.error("No scenarios generated")
            return None

        except subprocess.CalledProcessError as e:
            logger.error(f"Scenario generator failed: {e}")
            logger.error(f"STDOUT: {e.stdout}")
            logger.error(f"STDERR: {e.stderr}")
            return None

    def run_artifact_generator(self, use_case: Dict, scenarios_dir: Path, env: Dict) -> Optional[Path]:
        """Stage 3: Generate Garak artifacts"""
        if not self.config["stages"]["artifact_generator"]["enabled"]:
            logger.info("Artifact generator stage disabled, skipping...")
            return None

        logger.info(f"Stage 3: Artifact Generator for {use_case['id']}")

        output_dir = self.results_dir / use_case["id"] / "artifacts"
        output_dir.mkdir(parents=True, exist_ok=True)

        scenario_files = list(scenarios_dir.glob("*.yaml"))
        if not scenario_files:
            logger.error("No scenario files found")
            return None

        logger.info(f"Generating artifacts for {len(scenario_files)} scenarios...")

        examples_dir = Path(os.environ["ASAGO_EXAMPLES_DIR"])
        artifact_gen_dir = examples_dir / "asago-artifact-generator"
        if not artifact_gen_dir.exists():
            logger.error(f"Artifact generator directory not found at {artifact_gen_dir}")
            logger.info("Please clone asago-examples: git clone https://github.com/asago-ai/asago-examples")
            return None

        success_count = 0
        failures = []
        for scenario_file in scenario_files:
            cmd = [
                "uv",
                "run",
                "asago-artifact-generator",
                "generate",
                str(scenario_file),
                "-v",
                "--force",
                "--output-dir",
                str(output_dir),
            ]

            logger.info(f"Processing {scenario_file.name}...")

            try:
                result = subprocess.run(
                    cmd,
                    cwd=artifact_gen_dir,
                    env=env,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                success_count += 1
                logger.debug(result.stdout)

            except subprocess.TimeoutExpired:
                stderr_lines = "Timeout (no stderr captured)".split("\n")
                stderr_tail = stderr_lines[-20:]
                logger.warning(f"Artifact generation timed out for {scenario_file.name}")
                failures.append({"scenario_file": scenario_file.name, "returncode": 124, "stderr_tail": stderr_tail})
            except subprocess.CalledProcessError as e:
                stderr_lines = (e.stderr or "").split("\n")
                stderr_tail = stderr_lines[-20:]
                msg = (
                    f"Artifact generation failed for {scenario_file.name}: "
                    f"return code {e.returncode}\n"
                    f"Last 20 lines of stderr:\n{''.join(stderr_tail)}"
                )
                logger.warning(msg)
                failures.append(
                    {"scenario_file": scenario_file.name, "returncode": e.returncode, "stderr_tail": stderr_tail}
                )

        logger.info(f"Generated {success_count}/{len(scenario_files)} artifacts successfully")

        # Write failures.json
        failures_file = output_dir / "failures.json"
        with open(failures_file, "w") as f:
            json.dump(failures, f, indent=2)
        logger.info(f"Wrote {failures_file} with {len(failures)} failures")

        artifact_files = list(output_dir.glob("**/*-garak.json"))
        if artifact_files:
            logger.info(f"Found {len(artifact_files)} artifact files")
            return output_dir
        else:
            logger.error("No artifacts generated")
            return None

    def run_use_case(self, use_case: Dict) -> Dict:
        """Run full pipeline for one use case"""
        logger.info(f"Processing Use Case: {use_case['name']}")

        results = {"use_case_id": use_case["id"], "use_case_name": use_case["name"], "status": "started", "stages": {}}

        env = self._setup_env_vars()

        # Stage 1: Policy Mapper
        start_time = time.time()
        risks_file = self.run_policy_mapper(use_case, env)
        results["stages"]["policy_mapper"] = {
            "duration_seconds": time.time() - start_time,
            "output_file": str(risks_file) if risks_file else None,
            "status": "success" if risks_file else "failed",
        }

        if not risks_file:
            results["status"] = "failed_policy_mapper"
            return results

        # Stage 2: Scenario Generator
        start_time = time.time()
        scenarios_dir = self.run_scenario_generator(use_case, risks_file, env)
        results["stages"]["scenario_generator"] = {
            "duration_seconds": time.time() - start_time,
            "output_dir": str(scenarios_dir) if scenarios_dir else None,
            "status": "success" if scenarios_dir else "failed",
        }

        if not scenarios_dir:
            results["status"] = "failed_scenario_generator"
            return results

        # Stage 3: Artifact Generator
        start_time = time.time()
        artifacts_dir = self.run_artifact_generator(use_case, scenarios_dir, env)
        results["stages"]["artifact_generator"] = {
            "duration_seconds": time.time() - start_time,
            "output_dir": str(artifacts_dir) if artifacts_dir else None,
            "status": "success" if artifacts_dir else "failed",
        }

        if not artifacts_dir:
            results["status"] = "failed_artifact_generator"
            return results

        results["status"] = "completed"
        return results

    def save_run_summary(self, all_results: List[Dict]):
        """Save summary of all pipeline runs"""
        summary_file = self.results_dir / "pipeline_summary.json"

        summary = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "config": self.config, "results": all_results}

        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        logger.info(f"Pipeline summary saved to: {summary_file}")

    def run_all(self, specific_use_case_id: Optional[str] = None):
        """Run pipeline for all configured use cases"""
        use_cases = self.config["use_cases"]

        if specific_use_case_id:
            use_cases = [uc for uc in use_cases if uc["id"] == specific_use_case_id]
            if not use_cases:
                logger.error(f"Use case {specific_use_case_id} not found in config")
                return

        all_results = []

        for use_case in use_cases:
            result = self.run_use_case(use_case)
            all_results.append(result)

        self.save_run_summary(all_results)

        logger.info("PIPELINE SUMMARY")
        for result in all_results:
            status = "COMPLETED" if result["status"] == "completed" else "FAILED"
            logger.info(f"{result['use_case_name']}: {status}")


def main():
    parser = argparse.ArgumentParser(description="Run ASAGO pipeline automation")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to configuration file")
    parser.add_argument("--results-dir", type=str, default="./pipeline_results", help="Directory for pipeline results")
    parser.add_argument("--use-case-id", type=str, help="Run pipeline for specific use case only")

    args = parser.parse_args()

    script_dir = Path(__file__).parent
    config_path = script_dir / args.config if not Path(args.config).is_absolute() else Path(args.config)

    if not config_path.exists():
        logger.error(f"Config file not found: {config_path}")
        sys.exit(1)

    runner = PipelineRunner(str(config_path), args.results_dir)
    runner.run_all(specific_use_case_id=args.use_case_id)


if __name__ == "__main__":
    main()
