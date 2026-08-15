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
from .discovery import (
    WORKFLOW_ONLY_RULES,
    adapt_action_to_workflow,
    discover_targets,
    is_action_definition,
)
from .suppressions import apply_suppressions, load_suppressions


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


class ScannerError(Exception):
    """Raised when ghast itself fails while scanning a file.

    Distinct from a malformed workflow, which is reported as a finding.
    """


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
        #: Findings silenced by inline `# ghast: ignore` directives, so a run
        #: can report that suppressions are in play rather than hiding it.
        self.suppressed_count = 0
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
            workflow_only_rules: frozenset = frozenset()

            if is_action_definition(content):
                # A composite action runs steps with the same supply-chain
                # exposure as a workflow. Present them as a single-job workflow
                # so every step rule applies without knowing a second schema.
                adapted = adapt_action_to_workflow(content)
                if adapted is None:
                    # A JavaScript or Docker action has no steps to check.
                    return findings
                content = adapted
                workflow_only_rules = WORKFLOW_ONLY_RULES

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
            above_threshold = [
                finding
                for finding in engine_findings
                # Triggers, permissions and job timeouts have no analogue in an
                # action file; reporting them would be noise the author cannot
                # act on.
                if finding.rule_id not in workflow_only_rules
                and SEVERITY_LEVELS.index(normalize_severity(finding.severity))
                >= SEVERITY_LEVELS.index(normalized_threshold)
            ]

            # Inline `# ghast: ignore` directives are read from the raw text,
            # since the YAML parser discards comments.
            kept, suppressed = apply_suppressions(above_threshold, load_suppressions(file_path))
            self.suppressed_count += suppressed
            findings.extend(kept)

        except (yaml.YAMLError, OSError, UnicodeDecodeError) as e:
            # Problems with the file itself are a finding about the file.
            findings.append(
                Finding(
                    rule_id="file_error",
                    severity=Severity.MEDIUM,
                    message=f"Error parsing workflow file: {str(e)}",
                    file_path=file_path,
                    remediation="Ensure the file is valid YAML.",
                )
            )
        except Exception as e:
            # Anything else is a bug in ghast, not a problem with the user's
            # workflow. Reporting it as a MEDIUM finding about their file made
            # a completely broken scanner look like it was working: an
            # AttributeError once turned every scan into "Error parsing
            # workflow file" while reporting exit 0 for a clean repository.
            # Let it escape so the CLI exits 2 and CI actually goes red.
            raise ScannerError(
                f"ghast failed while scanning {file_path}: {type(e).__name__}: {e}. "
                "This is a bug in ghast; please report it."
            ) from e

        return findings

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

        for target in discover_targets(directory_path):
            findings.extend(self.scan_file(str(target.path), severity_threshold))

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

    targets = discover_targets(repo_path)
    all_findings: List[Finding] = []
    stats: Dict[str, Any] = {
        "start_time": datetime.now().isoformat(),
        "repo_path": repo_path,
        "total_files": 0,
        "total_findings": 0,
        "severity_counts": {level: 0 for level in SEVERITY_LEVELS},
        "rule_counts": {},
        "fixable_findings": 0,
        "suppressed_findings": 0,
    }

    if not targets:
        return all_findings, stats

    for target in targets:
        stats["total_files"] += 1
        file_findings = scanner.scan_file(str(target.path), severity_threshold)

        for finding in file_findings:
            stats["total_findings"] += 1
            stats["severity_counts"][finding.severity] = (
                stats["severity_counts"].get(finding.severity, 0) + 1
            )
            stats["rule_counts"][finding.rule_id] = stats["rule_counts"].get(finding.rule_id, 0) + 1

            if finding.can_fix:
                stats["fixable_findings"] += 1

        all_findings.extend(file_findings)

    stats["suppressed_findings"] = scanner.suppressed_count
    stats["end_time"] = datetime.now().isoformat()

    return all_findings, stats
