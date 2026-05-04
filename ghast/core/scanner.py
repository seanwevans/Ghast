"""
scanner.py - Core scanning functionality for ghast

This module handles the main scanning logic for GitHub Actions workflow files,
discovering security issues and providing findings.
"""

import re
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

from ..utils.yaml_handler import get_position, load_yaml_file_with_positions


class Severity(Enum):
    """Enumeration of finding severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_LEVELS = [level.value for level in Severity]


def normalize_severity(value: Union[str, Severity]) -> str:
    """Normalize severity values to canonical uppercase labels."""
    if isinstance(value, Severity):
        return value.value
    if isinstance(value, str):
        normalized = value.strip().upper()
        if normalized in SEVERITY_LEVELS:
            return normalized
    valid = ", ".join(SEVERITY_LEVELS)
    raise ValueError(f"Invalid severity level: {value}. Must be one of: {valid}")


@dataclass
class Finding:
    """Represents a security finding in a workflow file"""

    rule_id: str
    severity: Union[str, Severity]
    message: str
    file_path: str
    line_number: Optional[int] = None
    column: Optional[int] = None
    remediation: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    can_fix: bool = False

    def __post_init__(self) -> None:
        """Validate severity level"""
        self.severity = normalize_severity(self.severity)


class WorkflowScanner:
    """Scans GitHub Actions workflow files for security issues"""

    def __init__(self, strict: bool = False, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the scanner

        Args:
            strict: Enable stricter checking
            config: Configuration dictionary for rules
        """
        self.strict = strict
        self.config = config or {}
        from ..rules.engine import RuleEngine

        self.rule_engine = RuleEngine(config=self.config, strict=self.strict)

    def register_rule(
        self,
        rule_id: str,
        rule_func: Any,
        severity: Union[str, Severity] = Severity.MEDIUM,
        enabled: bool = True,
        description: Optional[str] = None,
    ) -> None:
        """
        Register a rule for scanning

        Args:
            rule_id: Unique identifier for the rule
            rule_func: Function that implements the rule
            severity: Default severity level for findings
            enabled: Whether the rule is enabled by default
            description: Human-readable description of the rule
        """

        # Backward compatibility shim: keep method available for callers that
        # may have extended WorkflowScanner directly. Rule registration is now
        # delegated to RuleEngine internals.
        _ = (rule_id, rule_func, severity, enabled, description)

    def register_default_rules(self) -> None:
        """Register the built-in rules"""
        # Backward compatibility shim: default rules are now owned by RuleEngine.
        return

    def scan_file(
        self, file_path: str, severity_threshold: str = Severity.LOW.value
    ) -> List[Finding]:
        """
        Scan a single workflow file for issues

        Args:
            file_path: Path to the workflow file
            severity_threshold: Minimum severity level to report

        Returns:
            List of findings
        """
        findings: List[Finding] = []
        normalized_threshold = normalize_severity(severity_threshold)

        try:
            content = load_yaml_file_with_positions(file_path)

            # Validate that the file appears to be a GitHub Actions workflow. If
            # the top-level structure is not a mapping or required keys are
            # missing, treat it as a parsing error so that users receive clear
            # feedback.
            if not isinstance(content, dict) or "jobs" not in content or "on" not in content:
                raise yaml.YAMLError("File is not a valid GitHub Actions workflow")

            engine_findings = self.rule_engine.scan_workflow(
                content,
                file_path,
                severity_threshold=normalized_threshold,
            )
            normalized_findings = self._normalize_rule_ids(engine_findings)
            findings.extend(
                [
                    finding
                    for finding in normalized_findings
                    if SEVERITY_LEVELS.index(normalize_severity(finding.severity))
                    >= SEVERITY_LEVELS.index(normalized_threshold)
                ]
            )

        except Exception as e:
            findings.append(
                Finding(
                    rule_id="file_error",
                    severity=Severity.MEDIUM,
                    message=f"Error parsing workflow file: {str(e)}",
                    file_path=file_path,
                    remediation="Ensure the file is valid YAML.",
                )
            )

        return findings

    def _normalize_rule_ids(self, findings: List[Finding]) -> List[Finding]:
        """Normalize engine rule IDs to scanner-compatible check_* naming."""
        normalized: List[Finding] = []
        for finding in findings:
            normalized_rule_id = finding.rule_id

            if finding.rule_id.startswith("rule_error."):
                _, _, raw_rule = finding.rule_id.partition(".")
                if not raw_rule.startswith("check_"):
                    normalized_rule_id = f"rule_error.check_{raw_rule}"
            elif not finding.rule_id.startswith("check_"):
                normalized_rule_id = f"check_{finding.rule_id}"

            normalized.append(replace(finding, rule_id=normalized_rule_id))
        return normalized

    def scan_directory(
        self, directory_path: str, severity_threshold: str = Severity.LOW.value
    ) -> List[Finding]:
        """
        Scan all workflow files in a directory

        Args:
            directory_path: Path to directory containing workflows
            severity_threshold: Minimum severity level to report

        Returns:
            List of findings
        """
        findings: List[Finding] = []

        workflow_dir = Path(directory_path) / ".github" / "workflows"
        if not workflow_dir.exists():
            return findings

        for file_path in workflow_dir.glob("*.y*ml"):
            file_findings = self.scan_file(str(file_path), severity_threshold)
            findings.extend(file_findings)

        return findings



def scan_repository(
    repo_path: str,
    strict: bool = False,
    config: Optional[Dict[str, Any]] = None,
    severity_threshold: str = Severity.LOW.value,
) -> Tuple[List[Finding], Dict[str, Any]]:
    """
    Scan a repository for workflow security issues

    Args:
        repo_path: Path to the repository
        strict: Enable strict checking
        config: Configuration for rules
        severity_threshold: Minimum severity level to report

    Returns:
        Tuple of (findings, stats)
    """
    scanner = WorkflowScanner(strict=strict, config=config)

    workflow_dir = Path(repo_path) / ".github" / "workflows"
    all_findings: List[Finding] = []
    stats: Dict[str, Any] = {
        "start_time": datetime.now().isoformat(),
        "repo_path": repo_path,
        "total_files": 0,
        "total_findings": 0,
        "severity_counts": {level: 0 for level in SEVERITY_LEVELS},
        "rule_counts": {},
        "fixable_findings": 0,
    }

    if not workflow_dir.exists():
        return all_findings, stats

    for workflow_file in workflow_dir.glob("*.y*ml"):
        stats["total_files"] += 1
        file_findings = scanner.scan_file(str(workflow_file), severity_threshold)

        for finding in file_findings:
            stats["total_findings"] += 1
            stats["severity_counts"][finding.severity] = (
                stats["severity_counts"].get(finding.severity, 0) + 1
            )
            stats["rule_counts"][finding.rule_id] = stats["rule_counts"].get(finding.rule_id, 0) + 1

            if finding.can_fix:
                stats["fixable_findings"] += 1

        all_findings.extend(file_findings)

    stats["end_time"] = datetime.now().isoformat()

    return all_findings, stats
