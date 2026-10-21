"""Smoke tests for asago-guardrails-recommender."""

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

from asago_guardrails_recommender import attacks, catalog, cli, deploy, recommend, test_rails

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestCatalogLoads:
    """Test catalog loading."""

    def test_catalog_loads(self):
        """Load catalog and verify 65 cards with unique ids."""
        cards = catalog.load_catalog(include_extended=True)
        assert len(cards) == 65, f"Expected 65 cards, got {len(cards)}"

        # Check ids are unique
        ids = [c.id for c in cards]
        assert len(ids) == len(set(ids)), "Card ids are not unique"


class TestExamplesLoad:
    """Test loading examples."""

    def test_examples_load_28_attacks(self):
        """Load attacks from examples/pipeline_results and verify 28 attacks."""
        atks = attacks.load_attacks(pipeline_results_path=REPO_ROOT / "examples/pipeline_results")
        assert len(atks) == 28, f"Expected 28 attacks, got {len(atks)}"


class TestRecommendRun:
    """Test recommend command and downstream tools."""

    def test_cached_run_reproduces_run1(self, recommend_run):
        """Run recommend with cache and compare to examples/run1."""
        # Load reference files from examples/run1
        run1_path = REPO_ROOT / "examples/run1"

        def normalize_json(content):
            """Normalize JSON by removing config_dir values."""
            obj = json.loads(content) if isinstance(content, str) else content
            normalized = re.sub(r'"config_dir": "[^"]*"', "", json.dumps(obj, sort_keys=True))
            return normalized

        # Compare signals.json
        with open(recommend_run / "signals.json") as f:
            run_signals = normalize_json(f.read())
        with open(run1_path / "signals.json") as f:
            ref_signals = normalize_json(f.read())
        assert run_signals == ref_signals, "signals.json does not match"

        # Compare candidates.json
        with open(recommend_run / "candidates.json") as f:
            run_candidates = normalize_json(f.read())
        with open(run1_path / "candidates.json") as f:
            ref_candidates = normalize_json(f.read())
        assert run_candidates == ref_candidates, "candidates.json does not match"

        # Compare recommendations.json
        with open(recommend_run / "recommendations.json") as f:
            run_recs = normalize_json(f.read())
        with open(run1_path / "recommendations.json") as f:
            ref_recs = normalize_json(f.read())
        assert run_recs == ref_recs, "recommendations.json does not match"

    def test_no_llm_run(self, tmp_path):
        """Run recommend with --no-llm flag."""
        output_dir = tmp_path / "output"
        recommend.main(
            [
                "--pipeline-results",
                str(REPO_ROOT / "examples/pipeline_results"),
                "--tag-cache",
                str(REPO_ROOT / "examples/tag_cache"),
                "--run-id",
                "no_llm",
                "--no-llm",
                "--out",
                str(output_dir),
            ]
        )

        # The output is in <output_dir>/<run_id>
        run_dir = output_dir / "no_llm"
        recs_path = run_dir / "recommendations.json"
        with open(recs_path) as f:
            recs = json.load(f)
        assert len(recs) == 28, f"Expected 28 recommendations, got {len(recs)}"

    def test_deploy_manifest(self, recommend_run, tmp_path):
        """Deploy manifests from a recommend run."""
        deploy.main(
            [
                "--run-dir",
                str(recommend_run),
                "--mode",
                "standalone",
                "--namespace",
                "test",
            ]
        )

        # Parse manifest
        manifest_path = recommend_run / "deploy-standalone.yaml"
        with open(manifest_path) as f:
            docs = list(yaml.safe_load_all(f))

        # Check for Deployment and Service
        kinds = {doc.get("kind") for doc in docs if doc}
        assert "Deployment" in kinds, "Missing Deployment in manifest"
        assert "Service" in kinds, "Missing Service in manifest"

        # Check for Deployment named "asago-rec"
        deployment = next((doc for doc in docs if doc and doc.get("kind") == "Deployment"), None)
        assert deployment is not None, "No Deployment found"
        assert deployment.get("metadata", {}).get("name") == "asago-rec", "Deployment not named asago-rec"

        # Check for Service named "asago-rec"
        service = next((doc for doc in docs if doc and doc.get("kind") == "Service"), None)
        assert service is not None, "No Service found"
        assert service.get("metadata", {}).get("name") == "asago-rec", "Service not named asago-rec"

        # Check for ConfigMap
        has_configmap = any(doc and doc.get("kind") == "ConfigMap" for doc in docs)
        assert has_configmap, "No ConfigMap found"

    def test_summarize_synthetic_records(self, tmp_path, capsys):
        """Summarize synthetic test records."""
        # Create synthetic records file
        records_file = tmp_path / "records.jsonl"
        records_data = [
            {
                "run_id": "test",
                "catalog_version": "abc123",
                "attack_id": "a1",
                "use_case": "test",
                "attack_features": {"threat_id": "T10", "signals": [{"signal": "test", "role": "essential"}]},
                "rails": ["rail1"],
                "option_rank": 1,
                "level": "detection",
                "status": "blocked",
                "blocking_rail": "rail1",
                "judge_outcome": None,
                "latency_ms": 100.0,
                "timestamp": "2024-01-01T00:00:00Z",
                "error": None,
                "test_label": "test",
            },
            {
                "run_id": "test",
                "catalog_version": "abc123",
                "attack_id": "a2",
                "use_case": "test",
                "attack_features": {"threat_id": "T10", "signals": [{"signal": "test", "role": "essential"}]},
                "rails": ["rail1"],
                "option_rank": 1,
                "level": "detection",
                "status": "passed",
                "blocking_rail": None,
                "judge_outcome": None,
                "latency_ms": 50.0,
                "timestamp": "2024-01-01T00:00:00Z",
                "error": None,
                "test_label": "test",
            },
            {
                "run_id": "test",
                "catalog_version": "abc123",
                "attack_id": "a3",
                "use_case": "test",
                "attack_features": {"threat_id": "T10", "signals": [{"signal": "test", "role": "essential"}]},
                "rails": ["rail1"],
                "option_rank": 1,
                "level": "detection",
                "status": "blocked",
                "blocking_rail": "rail1",
                "judge_outcome": None,
                "latency_ms": 120.0,
                "timestamp": "2024-01-01T00:00:00Z",
                "error": None,
                "test_label": "test",
            },
        ]
        with open(records_file, "w") as f:
            for record in records_data:
                f.write(json.dumps(record) + "\n")

        test_rails.main(
            [
                "--run-dir",
                str(REPO_ROOT / "examples/run1"),
                "--summarize",
                "--records",
                str(records_file),
            ]
        )

        captured = capsys.readouterr()
        assert "3" in captured.out, f"Expected '3' (record count) in output, got: {captured.out}"


class TestCLI:
    """Test CLI."""

    def test_cli_lists_commands(self, monkeypatch, capsys):
        """Test CLI --help shows all commands."""
        monkeypatch.setattr(sys, "argv", ["asago-guardrails-recommender", "--help"])

        with pytest.raises(SystemExit) as exc_info:
            cli.main()

        assert exc_info.value.code == 0, f"Expected exit code 0, got {exc_info.value.code}"

        captured = capsys.readouterr()
        output = captured.out

        # Check for all command names
        commands = ["recommend", "deploy", "test", "catalog-index", "snapshot"]
        for cmd in commands:
            assert cmd in output, f"Command '{cmd}' not found in help output"
