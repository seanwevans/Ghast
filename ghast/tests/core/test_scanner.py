"""
test_scanner.py - Tests for the scanner module
"""

from pathlib import Path

from ghast.core import WorkflowScanner, Finding, scan_repository, SEVERITY_LEVELS
from ghast.core.scanner import Severity
from ghast.utils import get_position, load_yaml_file_with_positions
from ghast.rules import RuleEngine
from ghast.utils import load_yaml_file_with_positions

import pytest


def _write_temp_workflow(temp_dir: str, filename: str, content: str) -> Path:
    """Helper to write a workflow file inside the temporary directory."""

    workflows_dir = Path(temp_dir) / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)

    workflow_path = workflows_dir / filename
    workflow_path.write_text(content)

    return workflow_path


def test_scanner_initialization():
    """Test scanner initialization with default and custom configs."""

    scanner = WorkflowScanner()
    assert hasattr(scanner, "rule_engine")
    assert scanner.rule_engine is not None

    custom_config = {
        "check_timeout": False,
        "check_shell": True,
        "severity_thresholds": {"check_deprecated": "HIGH"},
    }
    scanner = WorkflowScanner(config=custom_config)
    engine = scanner.rule_engine

    timeout_rule = engine.get_rule_by_id("timeout")
    shell_rule = engine.get_rule_by_id("shell_specification")
    deprecated_rule = engine.get_rule_by_id("deprecated_actions")

    assert timeout_rule is not None and not timeout_rule.enabled
    assert shell_rule is not None and shell_rule.enabled
    assert deprecated_rule is not None and deprecated_rule.severity == "HIGH"


def test_scan_file_matches_rule_engine_findings(patchable_workflow_file):
    """Scanner should delegate execution and preserve finding output shape/content."""

    scanner = WorkflowScanner()
    findings = scanner.scan_file(patchable_workflow_file)

    workflow = load_yaml_file_with_positions(patchable_workflow_file)
    engine = RuleEngine()
    expected_findings = engine.scan_workflow(workflow, patchable_workflow_file)

    assert [
        (f.rule_id, f.severity, f.message, f.line_number, f.column, f.can_fix) for f in findings
    ] == [
        (
            (
                f"rule_error.check_{f.rule_id.split('.', 1)[1]}"
                if f.rule_id.startswith("rule_error.")
                else (f.rule_id if f.rule_id.startswith("check_") else f"check_{f.rule_id}")
            ),
            f.severity,
            f.message,
            f.line_number,
            f.column,
            f.can_fix,
        )
        for f in expected_findings
    ]


def test_finding_severity_validation():
    """Test that Finding constructor validates severity levels."""

    finding = Finding(
        rule_id="test_rule",
        severity=Severity.HIGH,
        message="Test message",
        file_path="/path/to/file.yml",
    )
    assert finding.severity == Severity.HIGH.value

    with pytest.raises(ValueError):
        Finding(
            rule_id="test_rule",
            severity="INVALID",
            message="Test message",
            file_path="/path/to/file.yml",
        )


def test_check_timeout(patchable_workflow_file):
    """Test check_timeout rule."""
    scanner = WorkflowScanner()
    workflow = load_yaml_file_with_positions(patchable_workflow_file)

    findings = scanner.check_timeout(workflow, patchable_workflow_file)

    assert len(findings) > 0
    assert any("timeout" in finding.message.lower() for finding in findings)
    assert all(finding.rule_id == "check_timeout" for finding in findings)
    assert all(finding.can_fix for finding in findings)
    assert all(f.line_number is not None and f.column is not None for f in findings)


def test_check_shell(patchable_workflow_file):
    """Test check_shell rule."""
    scanner = WorkflowScanner()
    workflow = load_yaml_file_with_positions(patchable_workflow_file)

    findings = scanner.check_shell(workflow, patchable_workflow_file)

    assert len(findings) > 0
    assert any("shell" in finding.message.lower() for finding in findings)
    assert all(finding.rule_id == "check_shell" for finding in findings)
    assert all(f.line_number is not None and f.column is not None for f in findings)


def test_check_deprecated(patchable_workflow_file):
    """Test check_deprecated rule."""
    scanner = WorkflowScanner()
    workflow = load_yaml_file_with_positions(patchable_workflow_file)

    findings = scanner.check_deprecated(workflow, patchable_workflow_file)

    assert len(findings) > 0
    assert any("deprecated" in finding.message.lower() for finding in findings)
    assert all(finding.rule_id == "check_deprecated" for finding in findings)
    assert all(f.line_number is not None and f.column is not None for f in findings)


def test_check_action_pinning(action_pinning_workflow_file):
    """Test check_action_pinning rule."""

    scanner = WorkflowScanner()
    workflow = load_yaml_file_with_positions(action_pinning_workflow_file)

    findings = scanner.check_action_pinning(workflow, action_pinning_workflow_file)

    assert len(findings) == 2
    assert all(f.rule_id == "check_action_pinning" for f in findings)

    messages = {finding.message for finding in findings}
    assert any("unstable reference" in message for message in messages)
    assert any("not pinned" in message for message in messages)
    assert all(f.line_number is not None and f.column is not None for f in findings)

    severities = {finding.severity for finding in findings}
    assert Severity.HIGH.value in severities
    assert Severity.MEDIUM.value in severities
    assert all("0123456789abcdef0123456789abcdef01234567" not in message for message in messages)


def test_check_workflow_name(patchable_workflow_file):
    """Test check_workflow_name rule."""
    scanner = WorkflowScanner()
    workflow = load_yaml_file_with_positions(patchable_workflow_file)

    findings = scanner.check_workflow_name(workflow, patchable_workflow_file)

    assert len(findings) > 0
    assert any("workflow name" in finding.message.lower() for finding in findings)
    assert all(finding.rule_id == "check_workflow_name" for finding in findings)


def test_check_tokens(token_workflow_file):
    """Test check_tokens rule."""
    scanner = WorkflowScanner()
    workflow = load_yaml_file_with_positions(token_workflow_file)

    findings = scanner.check_tokens(workflow, token_workflow_file)

    assert len(findings) == 2
    messages = [f.message for f in findings]
    assert any("Hardcoded token" in m for m in messages)
    assert any("toJson(secrets)" in m for m in messages)

    steps = workflow["jobs"]["build"]["steps"]
    token_line = get_position(steps[0])[0]
    tojson_line = get_position(steps[2])[0]
    token_finding = next(f for f in findings if "Hardcoded token" in f.message)
    tojson_finding = next(f for f in findings if "toJson(secrets)" in f.message)
    assert token_finding.line_number == token_line
    assert tojson_finding.line_number == tojson_line
    assert token_finding.column is not None
    assert tojson_finding.column is not None


def test_check_permissions(patchable_workflow_file):
    """Test check_permissions rule for missing declarations."""

    scanner = WorkflowScanner()
    workflow = load_yaml_file_with_positions(patchable_workflow_file)

    findings = scanner.check_permissions(workflow, patchable_workflow_file)

    assert len(findings) == 2
    messages = {finding.message for finding in findings}
    assert "Missing explicit permissions at workflow level" in messages
    assert any("Missing explicit permissions in job" in message for message in messages)
    assert all(finding.rule_id == "check_permissions" for finding in findings)
    assert all(finding.severity == Severity.HIGH.value for finding in findings)


def test_check_reusable_inputs_with_declared_inputs(temp_dir):
    """Reusable workflows with declared inputs should not produce findings."""

    workflow_path = _write_temp_workflow(
        temp_dir,
        "reusable-valid.yml",
        """on:
  workflow_call:
    inputs:
      environment:
        required: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.environment }}"
""",
    )

    scanner = WorkflowScanner()
    workflow = load_yaml_file_with_positions(str(workflow_path))

    findings = scanner.check_reusable_inputs(workflow, str(workflow_path))

    assert findings == []


def test_check_reusable_inputs_missing_mapping(temp_dir):
    """Referencing inputs without declaring the inputs mapping should be flagged."""

    workflow_path = _write_temp_workflow(
        temp_dir,
        "reusable-missing-mapping.yml",
        """on:
  workflow_call:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.environment }}"
""",
    )

    scanner = WorkflowScanner()
    workflow = load_yaml_file_with_positions(str(workflow_path))

    findings = scanner.check_reusable_inputs(workflow, str(workflow_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "check_reusable_inputs"
    assert finding.severity == Severity.MEDIUM.value
    assert "not defined" in finding.message
    assert "environment" in finding.message

    steps = workflow["jobs"]["build"]["steps"]
    step_line = get_position(steps[0])[0]
    assert finding.line_number == step_line
    assert finding.column is not None


def test_check_reusable_inputs_missing_declaration(temp_dir):
    """Inputs referenced without a corresponding declaration should be reported."""

    workflow_path = _write_temp_workflow(
        temp_dir,
        "reusable-missing-declaration.yml",
        """on:
  workflow_call:
    inputs:
      existing:
        required: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.missing }}"
""",
    )

    scanner = WorkflowScanner()
    workflow = load_yaml_file_with_positions(str(workflow_path))

    findings = scanner.check_reusable_inputs(workflow, str(workflow_path))

    assert len(findings) == 1
    finding = findings[0]
    assert "not declared" in finding.message
    assert "missing" in finding.message
    assert finding.rule_id == "check_reusable_inputs"

    steps = workflow["jobs"]["build"]["steps"]
    assert finding.line_number == get_position(steps[0])[0]
    assert finding.column is not None


def test_check_reusable_inputs_handles_mixed_position_types(monkeypatch):
    """Sorting input references should not fail when some positions are missing."""

    workflow = {
        "on": {"workflow_call": {"inputs": {"existing": {"required": True}}}},
        "jobs": {
            "build": {
                "steps": [
                    {"run": 'echo "${{ inputs.missing }}"'},
                    {"run": 'echo "${{ inputs.missing }}"'},
                ]
            }
        },
    }

    first_step = workflow["jobs"]["build"]["steps"][0]
    second_step = workflow["jobs"]["build"]["steps"][1]

    def fake_get_position(node):
        if node is first_step:
            return (12, 3)
        if node is second_step:
            return (None, None)
        return (None, None)

    monkeypatch.setattr("ghast.core.scanner.get_position", fake_get_position)

    scanner = WorkflowScanner()
    findings = scanner.check_reusable_inputs(workflow, "reusable.yml")

    assert len(findings) == 2
    assert all(f.rule_id == "check_reusable_inputs" for f in findings)
    assert all("missing" in f.message for f in findings)


def test_check_ppe_vulnerabilities(insecure_workflow_file):
    """Test check_ppe_vulnerabilities rule."""
    scanner = WorkflowScanner()
    workflow = load_yaml_file_with_positions(insecure_workflow_file)

    findings = scanner.check_ppe_vulnerabilities(workflow, insecure_workflow_file)

    assert len(findings) > 0
    assert any("poisoned pipeline execution" in finding.message.lower() for finding in findings)
    assert all(finding.rule_id == "check_ppe_vulnerabilities" for finding in findings)
    assert all(finding.severity == "CRITICAL" for finding in findings)
    assert all(f.line_number is not None and f.column is not None for f in findings)


def test_check_command_injection(insecure_workflow_file):
    """Test check_command_injection rule."""
    scanner = WorkflowScanner()
    workflow = load_yaml_file_with_positions(insecure_workflow_file)

    findings = scanner.check_command_injection(workflow, insecure_workflow_file)

    assert len(findings) > 0
    assert any("untrusted" in finding.message.lower() for finding in findings)
    assert all(finding.rule_id == "check_command_injection" for finding in findings)
    assert all(f.line_number is not None and f.column is not None for f in findings)


def test_scan_file(patchable_workflow_file):
    """Test scanning a single file."""
    scanner = WorkflowScanner()

    findings = scanner.scan_file(patchable_workflow_file)

    assert len(findings) > 0
    assert any(f.rule_id == "check_permissions" for f in findings)

    for finding in findings:
        assert isinstance(finding, Finding)
        assert finding.rule_id
        assert finding.severity in SEVERITY_LEVELS
        assert finding.message
        assert finding.file_path == patchable_workflow_file
        if finding.line_number is not None:
            assert isinstance(finding.line_number, int)
        if finding.column is not None:
            assert isinstance(finding.column, int)


def test_scan_repository(mock_repo):
    """Test scanning an entire repository."""
    findings, stats = scan_repository(mock_repo)

    assert len(findings) > 0

    assert "total_files" in stats
    assert "total_findings" in stats
    assert "severity_counts" in stats
    assert "rule_counts" in stats
    assert "fixable_findings" in stats

    assert stats["total_findings"] == len(findings)
    assert sum(stats["severity_counts"].values()) == len(findings)
    assert sum(stats["rule_counts"].values()) == len(findings)
    assert stats["fixable_findings"] <= len(findings)


def test_severity_threshold_filtering(mock_repo):
    """Test filtering findings by severity threshold."""

    findings_low, _ = scan_repository(mock_repo, severity_threshold="LOW")

    findings_medium, _ = scan_repository(mock_repo, severity_threshold="MEDIUM")

    findings_high, _ = scan_repository(mock_repo, severity_threshold="HIGH")

    findings_critical, _ = scan_repository(mock_repo, severity_threshold="CRITICAL")

    assert len(findings_low) >= len(findings_medium) >= len(findings_high) >= len(findings_critical)

    for finding in findings_medium:
        assert SEVERITY_LEVELS.index(finding.severity) >= SEVERITY_LEVELS.index("MEDIUM")

    for finding in findings_high:
        assert SEVERITY_LEVELS.index(finding.severity) >= SEVERITY_LEVELS.index("HIGH")

    for finding in findings_critical:
        assert finding.severity == "CRITICAL"


def test_scan_nonexistent_directory():
    """Test scanning a non-existent directory."""
    findings, stats = scan_repository("/path/that/does/not/exist")

    assert len(findings) == 0
    assert stats["total_files"] == 0
    assert stats["total_findings"] == 0


def test_scan_malformed_yaml(temp_dir):
    """Test scanning a malformed YAML file."""

    workflows_dir = Path(temp_dir) / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)

    malformed_file = workflows_dir / "malformed.yml"
    malformed_file.write_text(
        """
    this is not valid yaml:
      - missing colon
        incorrect indentation
    """
    )

    scanner = WorkflowScanner()
    findings = scanner.scan_file(str(malformed_file))

    assert len(findings) > 0
    assert any("error parsing" in finding.message.lower() for finding in findings)
