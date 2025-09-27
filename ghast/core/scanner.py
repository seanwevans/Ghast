"""
scanner.py - Core scanning functionality for ghast

This module handles the main scanning logic for GitHub Actions workflow files,
discovering security issues and providing findings.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import yaml

from ..utils.yaml_handler import load_yaml_file_with_positions


class Severity(Enum):
    """Enumeration of finding severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_LEVELS = [level.value for level in Severity]


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
        if isinstance(self.severity, Severity):
            self.severity = self.severity.value
        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity level: {self.severity}")


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
        self.rule_registry: Dict[str, Dict[str, Any]] = {}
        self.register_default_rules()

    def register_rule(
        self,
        rule_id: str,
        rule_func: Callable[[Dict[str, Any], str], List[Finding]],
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

        if self.config and rule_id in self.config:
            enabled = self.config[rule_id]

        severity_config = self.config.get("severity_thresholds", {})
        if rule_id in severity_config:
            severity = severity_config[rule_id]

        if isinstance(severity, Severity):
            severity = severity.value

        self.rule_registry[rule_id] = {
            "func": rule_func,
            "enabled": enabled,
            "severity": severity,
            "description": description,
        }

    def register_default_rules(self) -> None:
        """Register the built-in rules"""
        self.register_rule(
            "check_timeout",
            self.check_timeout,
            severity=Severity.LOW,
            description="Ensures long jobs have timeout-minutes to prevent hanging",
        )

        self.register_rule(
            "check_shell",
            self.check_shell,
            severity=Severity.LOW,
            description="Adds shell: bash for multiline run: blocks",
        )

        self.register_rule(
            "check_deprecated",
            self.check_deprecated,
            severity=Severity.MEDIUM,
            description="Warns on old actions like actions/checkout@v1",
        )

        self.register_rule(
            "check_action_pinning",
            self.check_action_pinning,
            severity=Severity.MEDIUM,
            description="Detects GitHub Actions steps that are not pinned to a commit SHA",
        )

        self.register_rule(
            "check_runs_on",
            self.check_runs_on,
            severity=Severity.MEDIUM,
            description="Warns on ambiguous/self-hosted runners",
        )

        self.register_rule(
            "check_workflow_name",
            self.check_workflow_name,
            severity=Severity.LOW,
            description="Encourages top-level name: for visibility",
        )

        self.register_rule(
            "check_continue_on_error",
            self.check_continue_on_error,
            severity=Severity.MEDIUM,
            description="Warns if continue-on-error: true is used",
        )

        self.register_rule(
            "check_tokens",
            self.check_tokens,
            severity=Severity.HIGH,
            description="Flags hardcoded access tokens",
        )

        self.register_rule(
            "check_permissions",
            self.check_permissions,
            severity=Severity.HIGH,
            description="Requires explicit read-only permissions at workflow and job levels",
        )

        self.register_rule(
            "check_reusable_inputs",
            self.check_reusable_inputs,
            severity=Severity.MEDIUM,
            description="Ensures reusable workflows define proper inputs",
        )

        self.register_rule(
            "check_ppe_vulnerabilities",
            self.check_ppe_vulnerabilities,
            severity=Severity.CRITICAL,
            description="Detects Poisoned Pipeline Execution vulnerabilities",
        )

        self.register_rule(
            "check_command_injection",
            self.check_command_injection,
            severity=Severity.HIGH,
            description="Finds potential command injection vulnerabilities",
        )

        self.register_rule(
            "check_env_injection",
            self.check_env_injection,
            severity=Severity.HIGH,
            description="Detects unsafe modifications to GITHUB_ENV and GITHUB_PATH",
        )

        self.register_rule(
            "check_inline_bash",
            self.check_shell,
            severity=Severity.LOW,
            description="Alias for check_shell",
        )

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

        try:
            content = load_yaml_file_with_positions(file_path)

            # Validate that the file appears to be a GitHub Actions workflow. If
            # the top-level structure is not a mapping or required keys are
            # missing, treat it as a parsing error so that users receive clear
            # feedback.
            if not isinstance(content, dict) or "jobs" not in content or "on" not in content:
                raise yaml.YAMLError("File is not a valid GitHub Actions workflow")

            for rule_id, rule_info in self.rule_registry.items():
                if not rule_info["enabled"]:
                    continue

                rule_severity = rule_info["severity"]
                if SEVERITY_LEVELS.index(rule_severity) < SEVERITY_LEVELS.index(severity_threshold):
                    continue

                try:
                    rule_findings = rule_info["func"](content, file_path)
                    for finding in rule_findings:
                        findings.append(finding)
                except Exception as e:
                    findings.append(
                        Finding(
                            rule_id=f"rule_error.{rule_id}",
                            severity=Severity.LOW,
                            message=f"Error executing rule {rule_id}: {str(e)}",
                            file_path=file_path,
                            remediation="This is a bug in ghast. Please report it.",
                        )
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

    def check_timeout(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for missing timeout-minutes in long jobs"""
        findings: List[Finding] = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__"):
                continue
            steps = job.get("steps", [])

            # Count individual commands within multiline run steps to better
            # estimate the actual amount of work performed. Previously we only
            # counted the number of step objects which meant a single step with
            # many commands would evade the timeout recommendation.
            step_count = 0
            for step in steps:
                if isinstance(step, dict) and "run" in step and isinstance(step["run"], str):
                    # Count non-empty lines in the run block
                    lines = [ln for ln in step["run"].splitlines() if ln.strip()]
                    step_count += max(1, len(lines))
                else:
                    step_count += 1

            if "timeout-minutes" not in job and step_count > 5:
                findings.append(
                    Finding(
                        rule_id="check_timeout",
                        severity=Severity.LOW,
                        message=f"Job '{job_id}' has {step_count} steps but no timeout-minutes set",
                        file_path=file_path,
                        line_number=job.get("__line__"),
                        column=job.get("__column__"),
                        remediation=f"Add 'timeout-minutes: 15' to job '{job_id}'",
                        can_fix=True,
                    )
                )

        return findings

    def check_permissions(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Ensure workflows and jobs declare explicit, least-privilege permissions."""

        findings: List[Finding] = []

        remediation_workflow = "Add 'permissions: read-all' at the workflow level and specify write permissions only where needed"

        workflow_permissions = workflow.get("permissions")
        if workflow_permissions is None:
            findings.append(
                Finding(
                    rule_id="check_permissions",
                    severity=Severity.HIGH,
                    message="Missing explicit permissions at workflow level",
                    file_path=file_path,
                    line_number=workflow.get("__line__"),
                    column=workflow.get("__column__"),
                    remediation=remediation_workflow,
                    can_fix=True,
                )
            )
        elif isinstance(workflow_permissions, str) and workflow_permissions.lower() == "write-all":
            findings.append(
                Finding(
                    rule_id="check_permissions",
                    severity=Severity.HIGH,
                    message="Overly permissive workflow permissions (write-all)",
                    file_path=file_path,
                    line_number=workflow.get("__line__"),
                    column=workflow.get("__column__"),
                    remediation=remediation_workflow,
                )
            )

        remediation_job_template = (
            "Add 'permissions: read-all' to job '{job_id}' and elevate only what is required"
        )

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__"):
                continue

            permissions = job.get("permissions")
            if permissions is None:
                findings.append(
                    Finding(
                        rule_id="check_permissions",
                        severity=Severity.HIGH,
                        message=f"Missing explicit permissions in job '{job_id}'",
                        file_path=file_path,
                        line_number=job.get("__line__"),
                        column=job.get("__column__"),
                        remediation=remediation_job_template.format(job_id=job_id),
                        can_fix=True,
                    )
                )
            elif isinstance(permissions, str) and permissions.lower() == "write-all":
                findings.append(
                    Finding(
                        rule_id="check_permissions",
                        severity=Severity.HIGH,
                        message=f"Job '{job_id}' has overly permissive permissions (write-all)",
                        file_path=file_path,
                        line_number=job.get("__line__"),
                        column=job.get("__column__"),
                        remediation=remediation_job_template.format(job_id=job_id),
                    )
                )

        return findings

    def check_shell(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for multiline scripts without shell specified"""
        findings: List[Finding] = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__"):
                continue
            steps = job.get("steps", [])
            for step_idx, step in enumerate(steps):
                if isinstance(step, dict) and "run" in step and isinstance(step["run"], str):
                    if "\n" in step["run"] and "shell" not in step:
                        findings.append(
                            Finding(
                                rule_id="check_shell",
                                severity=Severity.LOW,
                                message=f"Multiline script in job '{job_id}' step {step_idx+1} has no shell specified",
                                file_path=file_path,
                                line_number=step.get("__line__"),
                                column=step.get("__column__"),
                                remediation="Add 'shell: bash' to this step",
                                can_fix=True,
                            )
                        )

        return findings

    def check_deprecated(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for deprecated actions"""
        findings: List[Finding] = []
        deprecated_actions = [
            ("actions/checkout@v1", "Use actions/checkout@v3 or later"),
            ("actions/setup-python@v1", "Use actions/setup-python@v4 or later"),
            ("actions/setup-node@v1", "Use actions/setup-node@v3 or later"),
            ("actions/cache@v1", "Use actions/cache@v3 or later"),
        ]

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__"):
                continue
            steps = job.get("steps", [])
            for step_idx, step in enumerate(steps):
                if isinstance(step, dict) and "uses" in step:
                    for deprecated, recommendation in deprecated_actions:
                        if step["uses"].startswith(deprecated):
                            findings.append(
                                Finding(
                                    rule_id="check_deprecated",
                                    severity=Severity.MEDIUM,
                                    message=f"Deprecated action '{step['uses']}' in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                    line_number=step.get("__line__"),
                                    column=step.get("__column__"),
                                    remediation=recommendation,
                                    can_fix=True,
                                )
                            )

        return findings

    def check_action_pinning(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check that actions are pinned to immutable commit SHAs."""

        findings: List[Finding] = []
        jobs = workflow.get("jobs", {})

        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__"):
                continue

            steps = job.get("steps", [])
            for step_idx, step in enumerate(steps):
                if not isinstance(step, dict) or "uses" not in step:
                    continue

                action = step["uses"]
                line_number = step.get("__line__")
                column_number = step.get("__column__")

                if re.search(r"@(main|master)$", action):
                    findings.append(
                        Finding(
                            rule_id="check_action_pinning",
                            severity=Severity.HIGH,
                            message=(
                                f"Step {step_idx + 1} in job '{job_id}' uses unstable reference: {action}"
                            ),
                            file_path=file_path,
                            line_number=line_number,
                            column=column_number,
                            remediation="Pin the action to a specific commit SHA",
                            can_fix=False,
                        )
                    )
                elif not re.search(r"@[0-9a-fA-F]{39,40}$", action):
                    findings.append(
                        Finding(
                            rule_id="check_action_pinning",
                            severity=Severity.MEDIUM,
                            message=(
                                f"Step {step_idx + 1} in job '{job_id}' is not pinned to a specific commit SHA: {action}"
                            ),
                            file_path=file_path,
                            line_number=line_number,
                            column=column_number,
                            remediation="Pin the action to a specific commit SHA for better security",
                            can_fix=False,
                        )
                    )

        return findings

    def check_runs_on(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for self-hosted or ambiguous runners"""
        findings: List[Finding] = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__"):
                continue
            runs_on = job.get("runs-on", "")

            if not runs_on:
                findings.append(
                    Finding(
                        rule_id="check_runs_on",
                        severity=Severity.MEDIUM,
                        message=f"Missing 'runs-on' in job '{job_id}'",
                        file_path=file_path,
                        line_number=job.get("__line__"),
                        column=job.get("__column__"),
                        remediation="Specify a runner, e.g., 'runs-on: ubuntu-latest'",
                        can_fix=True,
                    )
                )
            elif runs_on == "self-hosted":
                findings.append(
                    Finding(
                        rule_id="check_runs_on",
                        severity=Severity.MEDIUM,
                        message=f"Job '{job_id}' uses self-hosted runner without labels",
                        file_path=file_path,
                        line_number=job.get("__line__"),
                        column=job.get("__column__"),
                        remediation="Add specific labels to self-hosted runners for better security isolation",
                        can_fix=False,
                    )
                )
            elif isinstance(runs_on, list) and "self-hosted" in runs_on:
                findings.append(
                    Finding(
                        rule_id="check_runs_on",
                        severity=Severity.LOW if len(runs_on) > 1 else Severity.MEDIUM,
                        message=f"Job '{job_id}' uses self-hosted runner",
                        file_path=file_path,
                        line_number=job.get("__line__"),
                        column=job.get("__column__"),
                        remediation="Consider using GitHub-hosted runners for better security isolation",
                        can_fix=False,
                    )
                )

        return findings

    def check_workflow_name(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for missing workflow name"""
        findings: List[Finding] = []

        if "name" not in workflow:
            findings.append(
                Finding(
                    rule_id="check_workflow_name",
                    severity=Severity.LOW,
                    message="Missing workflow name (top-level 'name' field)",
                    file_path=file_path,
                    remediation="Add a 'name:' field at the top level of the workflow",
                    can_fix=True,
                )
            )

        return findings

    def check_continue_on_error(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for continue-on-error: true"""
        findings: List[Finding] = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__"):
                continue
            if job.get("continue-on-error") is True:
                findings.append(
                    Finding(
                        rule_id="check_continue_on_error",
                        severity=Severity.MEDIUM,
                        message=f"Job '{job_id}' has 'continue-on-error: true'",
                        file_path=file_path,
                        line_number=job.get("__line__"),
                        column=job.get("__column__"),
                        remediation="Remove 'continue-on-error' or set to false to ensure workflow fails on error",
                        can_fix=False,
                    )
                )

            steps = job.get("steps", [])
            for step_idx, step in enumerate(steps):
                if isinstance(step, dict) and step.get("continue-on-error") is True:
                    findings.append(
                        Finding(
                            rule_id="check_continue_on_error",
                            severity=Severity.MEDIUM,
                            message=f"Step {step_idx+1} in job '{job_id}' has 'continue-on-error: true'",
                            file_path=file_path,
                            line_number=step.get("__line__"),
                            column=step.get("__column__"),
                            remediation="Remove 'continue-on-error' or set to false to ensure workflow fails on error",
                            can_fix=False,
                        )
                    )

        return findings

    def check_tokens(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for hardcoded tokens"""
        findings: List[Finding] = []

        token_patterns = [
            (r'token\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}["\']?', "Hardcoded token"),
            (
                r'api[_\-]?key\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}["\']?',
                "Hardcoded API key",
            ),
            (
                r'auth[_\-]?token\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}["\']?',
                "Hardcoded auth token",
            ),
            (r'password\s*[:=]\s*["\']?[^"\']{8,}["\']?', "Hardcoded password"),
            (r'secret\s*[:=]\s*["\']?[^"\']{8,}["\']?', "Hardcoded secret"),
            (
                r'access[_\-]?key\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?',
                "Hardcoded access key",
            ),
            (
                r'gh[_\-]?token\s*[:=]\s*["\']?[A-Za-z0-9_\-]{30,}["\']?',
                "Hardcoded GitHub token",
            ),
        ]

        def walk(node: Any, line: Optional[int] = None, column: Optional[int] = None) -> None:
            if isinstance(node, dict):
                current_line = node.get("__line__", line)
                current_column = node.get("__column__", column)
                for key, value in node.items():
                    if key in ("__line__", "__column__"):
                        continue
                    value_line = getattr(value, "__line__", None)
                    value_column = getattr(value, "__column__", None)
                    walk(
                        value,
                        value_line if value_line is not None else current_line,
                        value_column if value_column is not None else current_column,
                    )
            elif isinstance(node, list):
                current_line = getattr(node, "__line__", line)
                current_column = getattr(node, "__column__", column)
                for item in node:
                    item_line = getattr(item, "__line__", None)
                    item_column = getattr(item, "__column__", None)
                    walk(
                        item,
                        item_line if item_line is not None else current_line,
                        item_column if item_column is not None else current_column,
                    )
            else:
                if not isinstance(node, str):
                    return
                if "toJson(secrets)" in node:
                    findings.append(
                        Finding(
                            rule_id="check_tokens",
                            severity=Severity.CRITICAL,
                            message="Dangerous 'toJson(secrets)' usage exposes all secrets",
                            file_path=file_path,
                            line_number=line,
                            column=column,
                            remediation="Never use toJson(secrets), reference individual secrets explicitly",
                            can_fix=False,
                        )
                    )
                    return
                if "secrets." in node or "${{" in node:
                    return
                for pattern, desc in token_patterns:
                    for _ in re.finditer(pattern, node, re.IGNORECASE):
                        findings.append(
                            Finding(
                                rule_id="check_tokens",
                                severity=Severity.HIGH,
                                message=f"{desc} found in workflow file",
                                file_path=file_path,
                                line_number=line,
                                column=column,
                                remediation="Replace hardcoded tokens with secrets, e.g., ${{ secrets.GITHUB_TOKEN }}",
                                can_fix=False,
                            )
                        )

        walk(workflow)
        return findings

    def check_reusable_inputs(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for reusable workflows that don't properly define inputs"""
        findings: List[Finding] = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__"):
                continue
            if job.get("uses") and "with" in job:
                if not job.get("inputs"):
                    findings.append(
                        Finding(
                            rule_id="check_reusable_inputs",
                            severity=Severity.MEDIUM,
                            message=f"Reusable workflow in job '{job_id}' uses 'with' without defining 'inputs'",
                            file_path=file_path,
                            line_number=job.get("__line__"),
                            column=job.get("__column__"),
                            remediation="Define explicit 'inputs' for reusable workflows",
                            can_fix=False,
                        )
                    )

        return findings

    def check_ppe_vulnerabilities(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for Poisoned Pipeline Execution vulnerabilities"""
        findings: List[Finding] = []
        high_risk_triggers = {"pull_request_target", "workflow_run"}

        on_section = workflow.get("on", {})
        triggers = set()

        if isinstance(on_section, dict):
            triggers = set(on_section.keys())
        elif isinstance(on_section, list):
            triggers = set(on_section)

        high_risk_triggers_used = triggers.intersection(high_risk_triggers)

        if not high_risk_triggers_used:
            return findings

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__"):
                continue
            steps = job.get("steps", [])

            checkout_found = False
            untrusted_ref_used = False
            untrusted_ref_value = None

            for step in steps:
                if isinstance(step, dict) and "uses" in step:
                    uses = step["uses"]

                    if uses.startswith("actions/checkout"):
                        checkout_found = True

                        if "with" in step and "ref" in step["with"]:
                            ref = step["with"]["ref"]
                            dangerous_refs = [
                                "github.event.pull_request",
                                "github.head_ref",
                                "github.event.issue",
                                "github.event.comment",
                                "github.event.review",
                            ]

                            for dangerous_ref in dangerous_refs:
                                if dangerous_ref in str(ref):
                                    untrusted_ref_used = True
                                    untrusted_ref_value = ref
                                    break

            if checkout_found and untrusted_ref_used:
                findings.append(
                    Finding(
                        rule_id="check_ppe_vulnerabilities",
                        severity=Severity.CRITICAL,
                        message=f"Poisoned Pipeline Execution vulnerability: job '{job_id}' uses {', '.join(high_risk_triggers_used)} trigger with checkout of untrusted code",
                        file_path=file_path,
                        line_number=job.get("__line__"),
                        column=job.get("__column__"),
                        remediation="Use pull_request trigger instead, or if pull_request_target is required, do not check out untrusted code or use dedicated jobs with restricted permissions.",
                        can_fix=False,
                        context={
                            "triggers": list(high_risk_triggers_used),
                            "ref": untrusted_ref_value,
                        },
                    )
                )

            if "secrets" in job and job["secrets"] == "inherit" and high_risk_triggers_used:
                findings.append(
                    Finding(
                        rule_id="check_ppe_vulnerabilities",
                        severity=Severity.CRITICAL,
                        message=f"High-risk secret exposure: job '{job_id}' uses 'secrets: inherit' with {', '.join(high_risk_triggers_used)} trigger",
                        file_path=file_path,
                        line_number=job.get("__line__"),
                        column=job.get("__column__"),
                        remediation="Explicitly pass only required secrets to jobs, or use 'repositories' field to restrict which repos can use this workflow",
                        can_fix=False,
                        context={"triggers": list(high_risk_triggers_used)},
                    )
                )

        return findings

    def check_command_injection(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for potential command injection vulnerabilities"""
        findings: List[Finding] = []

        # ``run_command`` contains only the script body, so the previous
        # implementation erroneously looked for the literal ``"run:"`` prefix
        # and therefore never matched any dangerous patterns.  This prevented
        # the rule from flagging obvious injection vectors.  The regular
        # expressions below operate directly on the command text, ensuring that
        # untrusted GitHub event data is correctly detected.
        dangerous_patterns = [
            (
                r"\${{.*github\.event\.(issue|comment|review).*}}",
                "Untrusted event data in shell command",
            ),
            (
                r"\${{.*github\.head_ref.*}}",
                "Untrusted head_ref in shell command",
            ),
            (
                r"\${{.*github\.event\.pull_request\.title.*}}",
                "Untrusted PR title in shell command",
            ),
            (
                r"\${{.*github\.event\.pull_request\.body.*}}",
                "Untrusted PR body in shell command",
            ),
        ]

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__"):
                continue
            steps = job.get("steps", [])
            for step_idx, step in enumerate(steps):
                if isinstance(step, dict) and "run" in step and isinstance(step["run"], str):
                    run_command = step["run"]

                    for pattern, desc in dangerous_patterns:
                        if re.search(pattern, run_command, re.DOTALL):
                            findings.append(
                                Finding(
                                    rule_id="check_command_injection",
                                    severity=Severity.HIGH,
                                    message=f"{desc} in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                    line_number=step.get("__line__"),
                                    column=step.get("__column__"),
                                    remediation="Never use untrusted input directly in shell commands. Use input validation or environment variables with proper quoting.",
                                    can_fix=False,
                                )
                            )

                    if "${{ env." in run_command:
                        if self.strict:
                            findings.append(
                                Finding(
                                    rule_id="check_command_injection",
                                    severity=Severity.MEDIUM,
                                    message=f"Environment variable interpolation in shell command in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                    line_number=step.get("__line__"),
                                    column=step.get("__column__"),
                                    remediation="Be careful with environment variable interpolation in shell commands. Consider using proper quoting.",
                                    can_fix=False,
                                )
                            )

        return findings

    def check_env_injection(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for unsafe modifications to GITHUB_ENV and GITHUB_PATH"""
        findings: List[Finding] = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job_id in ("__line__", "__column__"):
                continue
            steps = job.get("steps", [])

            checkout_step_idx = None
            for step_idx, step in enumerate(steps):
                if (
                    isinstance(step, dict)
                    and "uses" in step
                    and step["uses"].startswith("actions/checkout")
                ):
                    checkout_step_idx = step_idx
                    break

            if checkout_step_idx is not None:
                for step_idx, step in enumerate(steps):
                    if step_idx <= checkout_step_idx:
                        continue

                    if isinstance(step, dict) and "run" in step and isinstance(step["run"], str):
                        run_command = step["run"]

                        if (
                            "GITHUB_ENV" in run_command
                            or ">>$GITHUB_ENV" in run_command
                            or ">> $GITHUB_ENV" in run_command
                        ):
                            findings.append(
                                Finding(
                                    rule_id="check_env_injection",
                                    severity=Severity.HIGH,
                                    message=f"Modification of GITHUB_ENV after checkout in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                    line_number=step.get("__line__"),
                                    column=step.get("__column__"),
                                    remediation="Avoid modifying GITHUB_ENV after checking out untrusted code, or move environment settings before checkout.",
                                    can_fix=False,
                                )
                            )

                        if (
                            "GITHUB_PATH" in run_command
                            or ">>$GITHUB_PATH" in run_command
                            or ">> $GITHUB_PATH" in run_command
                        ):
                            findings.append(
                                Finding(
                                    rule_id="check_env_injection",
                                    severity=Severity.HIGH,
                                    message=f"Modification of GITHUB_PATH after checkout in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                    line_number=step.get("__line__"),
                                    column=step.get("__column__"),
                                    remediation="Avoid modifying GITHUB_PATH after checking out untrusted code, or move path modifications before checkout.",
                                    can_fix=False,
                                )
                            )

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
