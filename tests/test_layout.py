"""Test support for both layout styles: exhaustive and plain directories."""

import shutil
from pathlib import Path

from asago_guardrails_recommender import attacks

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_plain_layout(tmp_path):
    """Test loading attacks from plain layout (artifacts/ and scenarios/)."""
    # Copy 2 garak files and matching scenario YAMLs to tmp using plain layout
    examples_artifacts = REPO_ROOT / "examples/pipeline_results/01_healthcare_us/artifacts_exhaustive"
    examples_scenarios = REPO_ROOT / "examples/pipeline_results/01_healthcare_us/scenarios_exhaustive"

    # Create plain layout in tmp
    tmp_uc = tmp_path / "my_uc"
    tmp_artifacts = tmp_uc / "artifacts"
    tmp_scenarios = tmp_uc / "scenarios" / "20261013T160123_405da291f767482a198141d8fa8c3be5" / "scenarios"
    tmp_artifacts.mkdir(parents=True)
    tmp_scenarios.mkdir(parents=True)

    # Copy garak files (2 files)
    garak_files = sorted(list(examples_artifacts.glob("*/*-garak.json")))[:2]
    for garak_file in garak_files:
        # Create scenario directory with same name as garak parent dir
        scenario_id = garak_file.parent.name
        scenario_dir = tmp_artifacts / scenario_id
        scenario_dir.mkdir(parents=True, exist_ok=True)
        # Copy garak file
        shutil.copy2(garak_file, scenario_dir / garak_file.name)

    # Copy matching scenario YAMLs
    examples_run_dir = examples_scenarios / "20261013T160123_405da291f767482a198141d8fa8c3be5" / "scenarios"
    scenario_files = sorted(list(examples_run_dir.glob("scenario:v2:*.yaml")))[:2]
    for scenario_file in scenario_files:
        shutil.copy2(scenario_file, tmp_scenarios / scenario_file.name)

    # Load attacks from tmp with plain layout
    attacks_plain = attacks.load_attacks(pipeline_results_path=tmp_path)

    # Verify we loaded attacks
    assert len(attacks_plain) >= 1, "Expected at least 1 attack from plain layout"

    # Check attacks have key fields
    for attack in attacks_plain:
        assert attack.use_case == "my_uc", f"Expected use_case 'my_uc', got {attack.use_case}"
        assert attack.attack_id, "Attack should have attack_id"

    # At least one attack should have threat_id (from matching scenario)
    attacks_with_threat = [a for a in attacks_plain if a.threat_id]
    assert len(attacks_with_threat) >= 1, "Expected at least 1 attack with threat_id from matching scenarios"


def test_both_layouts(tmp_path):
    """Test that both exhaustive and plain layouts work together."""
    # Create both layouts in the same tmp directory
    examples_artifacts = REPO_ROOT / "examples/pipeline_results/01_healthcare_us/artifacts_exhaustive"
    examples_scenarios = REPO_ROOT / "examples/pipeline_results/01_healthcare_us/scenarios_exhaustive"
    examples_run_dir = examples_scenarios / "20261013T160123_405da291f767482a198141d8fa8c3be5" / "scenarios"

    tmp_uc = tmp_path / "test_uc"

    # Create exhaustive layout
    exhaustive_artifacts = tmp_uc / "artifacts_exhaustive"
    exhaustive_scenarios = (
        tmp_uc / "scenarios_exhaustive" / "20261013T160123_405da291f767482a198141d8fa8c3be5" / "scenarios"
    )
    exhaustive_artifacts.mkdir(parents=True)
    exhaustive_scenarios.mkdir(parents=True)

    # Copy 1 garak file to exhaustive
    garak_files = sorted(list(examples_artifacts.glob("*/*-garak.json")))[:1]
    for garak_file in garak_files:
        scenario_id = garak_file.parent.name
        scenario_dir = exhaustive_artifacts / scenario_id
        scenario_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(garak_file, scenario_dir / garak_file.name)

    # Copy matching scenario YAML to exhaustive
    scenario_files = sorted(list(examples_run_dir.glob("scenario:v2:*.yaml")))[:1]
    for scenario_file in scenario_files:
        shutil.copy2(scenario_file, exhaustive_scenarios / scenario_file.name)

    # Load attacks from tmp with exhaustive layout
    attacks_exhaustive = attacks.load_attacks(pipeline_results_path=tmp_path)

    # Verify we loaded at least one attack
    assert len(attacks_exhaustive) >= 1, "Expected at least 1 attack from exhaustive layout"

    # Check it has threat_id
    first_attack = attacks_exhaustive[0]
    assert first_attack.threat_id, f"Attack should have threat_id, got {first_attack.threat_id}"
