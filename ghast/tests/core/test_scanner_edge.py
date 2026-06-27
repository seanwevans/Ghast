"""
test_scanner_edge.py - Edge-case coverage for the workflow scanner

Covers the backward-compatibility shims, rule-id normalization for
``rule_error.*`` findings, and the directory-scanning helper.
"""

from pathlib import Path

from ghast.core import Finding
from ghast.core.scanner import Severity, WorkflowScanner


def test_register_rule_shim_is_noop():
    scanner = WorkflowScanner()
    # Should accept the legacy signature without raising or registering.
    assert scanner.register_rule("custom", lambda w, f: [], severity="HIGH") is None


def test_register_default_rules_shim_is_noop():
    scanner = WorkflowScanner()
    assert scanner.register_default_rules() is None


def test_normalize_rule_ids_for_rule_error():
    scanner = WorkflowScanner()
    findings = [
        Finding(rule_id="rule_error.permissions", severity="LOW", message="m", file_path="f"),
        Finding(rule_id="rule_error.check_timeout", severity="LOW", message="m", file_path="f"),
        Finding(rule_id="permissions", severity="HIGH", message="m", file_path="f"),
        Finding(rule_id="check_timeout", severity="LOW", message="m", file_path="f"),
    ]
    normalized = scanner._normalize_rule_ids(findings)
    ids = [f.rule_id for f in normalized]
    assert ids == [
        "rule_error.check_permissions",
        "rule_error.check_timeout",
        "check_permissions",
        "check_timeout",
    ]


def test_scan_directory_without_workflows(temp_dir):
    scanner = WorkflowScanner()
    assert scanner.scan_directory(temp_dir) == []


def test_scan_directory_with_workflows(insecure_workflow_file, temp_dir):
    # insecure_workflow_file already lives under temp_dir/.github/workflows
    scanner = WorkflowScanner()
    findings = scanner.scan_directory(temp_dir, severity_threshold=Severity.LOW.value)
    assert len(findings) > 0
    assert all(isinstance(f, Finding) for f in findings)
