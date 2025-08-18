"""
test_scanner.py - Tests for the scanner module
"""

import os
import pytest
from pathlib import Path
import yaml

from ghast.core import WorkflowScanner, Finding, scan_repository, SEVERITY_LEVELS
from ghast.core.scanner import Severity


def test_scanner_initialization():
    """Test scanner initialization with default and custom configs."""

    scanner = WorkflowScanner()
    assert hasattr(scanner, "rule_registry")
    assert len(scanner.rule_registry) > 0

    custom_config = {
        "check_timeout": False,
        "check_shell": True,
        "severity_thresholds": {"check_deprecated": "HIGH"},
    }
    scanner = WorkflowScanner(config=custom_config)

    assert not scanner.rule_registry["check_timeout"]["enabled"]
    assert scanner.rule_registry["check_shell"]["enabled"]

    assert scanner.rule_registry["check_deprecated"]["severity"] == "HIGH"


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

    with open(patchable_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    findings = scanner.check_timeout(workflow, patchable_workflow_file)

    assert len(findings) > 0
    assert any("timeout" in finding.message.lower() for finding in findings)
    assert all(finding.rule_id == "check_timeout" for finding in findings)
    assert all(finding.can_fix for finding in findings)


def test_check_shell(patchable_workflow_file):
    """Test check_shell rule."""
    scanner = WorkflowScanner()

    with open(patchable_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    findings = scanner.check_shell(workflow, patchable_workflow_file)

    assert len(findings) > 0
    assert any("shell" in finding.message.lower() for finding in findings)
    assert all(finding.rule_id == "check_shell" for finding in findings)


def test_check_deprecated(patchable_workflow_file):
    """Test check_deprecated rule."""
    scanner = WorkflowScanner()

    with open(patchable_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    findings = scanner.check_deprecated(workflow, patchable_workflow_file)

    assert len(findings) > 0
    assert any("deprecated" in finding.message.lower() for finding in findings)
    assert all(finding.rule_id == "check_deprecated" for finding in findings)


def test_check_workflow_name(patchable_workflow_file):
    """Test check_workflow_name rule."""
    scanner = WorkflowScanner()

    with open(patchable_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    findings = scanner.check_workflow_name(workflow, patchable_workflow_file)

    assert len(findings) > 0
    assert any("workflow name" in finding.message.lower() for finding in findings)
    assert all(finding.rule_id == "check_workflow_name" for finding in findings)


def test_check_ppe_vulnerabilities(insecure_workflow_file):
    """Test check_ppe_vulnerabilities rule."""
    scanner = WorkflowScanner()

    with open(insecure_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    findings = scanner.check_ppe_vulnerabilities(workflow, insecure_workflow_file)

    assert len(findings) > 0
    assert any("poisoned pipeline execution" in finding.message.lower() for finding in findings)
    assert all(finding.rule_id == "check_ppe_vulnerabilities" for finding in findings)
    assert all(finding.severity == "CRITICAL" for finding in findings)


def test_check_command_injection(insecure_workflow_file):
    """Test check_command_injection rule."""
    scanner = WorkflowScanner()

    with open(insecure_workflow_file, "r") as f:
        workflow = yaml.safe_load(f)

    findings = scanner.check_command_injection(workflow, insecure_workflow_file)

    assert len(findings) > 0
    assert any("untrusted" in finding.message.lower() for finding in findings)
    assert all(finding.rule_id == "check_command_injection" for finding in findings)


def test_scan_file(patchable_workflow_file):
    """Test scanning a single file."""
    scanner = WorkflowScanner()

    findings = scanner.scan_file(patchable_workflow_file)

    assert len(findings) > 0

    for finding in findings:
        assert isinstance(finding, Finding)
        assert finding.rule_id
        assert finding.severity in SEVERITY_LEVELS
        assert finding.message
        assert finding.file_path == patchable_workflow_file


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
