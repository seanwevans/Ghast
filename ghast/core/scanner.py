"""
scanner.py - Core scanning functionality for ghast

This module handles the main scanning logic for GitHub Actions workflow files,
discovering security issues and providing findings.
"""

import os
import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime

SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class Finding:
    """Represents a security finding in a workflow file"""

    rule_id: str
    severity: str
    message: str
    file_path: str
    line_number: Optional[int] = None
    column: Optional[int] = None
    remediation: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
    can_fix: bool = False

    def __post_init__(self):
        """Validate severity level"""
        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity level: {self.severity}")


class WorkflowScanner:
    """
    Scans GitHub Actions workflow files for security issues
    """

    def __init__(self, strict=False, config=None):
        """
        Initialize the scanner

        Args:
            strict: Enable stricter checking
            config: Configuration dictionary for rules
        """
        self.strict = strict
        self.config = config or {}
        self.rule_registry = {}
        self.register_default_rules()

    def register_rule(self, rule_id, rule_func, severity="MEDIUM", enabled=True, description=None):
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

        self.rule_registry[rule_id] = {
            "func": rule_func,
            "enabled": enabled,
            "severity": severity,
            "description": description,
        }

    def register_default_rules(self):
        """Register the built-in rules"""
        self.register_rule(
            "check_timeout",
            self.check_timeout,
            severity="LOW",
            description="Ensures long jobs have timeout-minutes to prevent hanging",
        )

        self.register_rule(
            "check_shell",
            self.check_shell,
            severity="LOW",
            description="Adds shell: bash for multiline run: blocks",
        )

        self.register_rule(
            "check_deprecated",
            self.check_deprecated,
            severity="MEDIUM",
            description="Warns on old actions like actions/checkout@v1",
        )

        self.register_rule(
            "check_runs_on",
            self.check_runs_on,
            severity="MEDIUM",
            description="Warns on ambiguous/self-hosted runners",
        )

        self.register_rule(
            "check_workflow_name",
            self.check_workflow_name,
            severity="LOW",
            description="Encourages top-level name: for visibility",
        )

        self.register_rule(
            "check_continue_on_error",
            self.check_continue_on_error,
            severity="MEDIUM",
            description="Warns if continue-on-error: true is used",
        )

        self.register_rule(
            "check_tokens",
            self.check_tokens,
            severity="HIGH",
            description="Flags hardcoded access tokens",
        )

        self.register_rule(
            "check_reusable_inputs",
            self.check_reusable_inputs,
            severity="MEDIUM",
            description="Ensures reusable workflows define proper inputs",
        )

        self.register_rule(
            "check_ppe_vulnerabilities",
            self.check_ppe_vulnerabilities,
            severity="CRITICAL",
            description="Detects Poisoned Pipeline Execution vulnerabilities",
        )

        self.register_rule(
            "check_command_injection",
            self.check_command_injection,
            severity="HIGH",
            description="Finds potential command injection vulnerabilities",
        )

        self.register_rule(
            "check_env_injection",
            self.check_env_injection,
            severity="HIGH",
            description="Detects unsafe modifications to GITHUB_ENV and GITHUB_PATH",
        )

        self.register_rule(
            "check_inline_bash",
            self.check_shell,
            severity="LOW",
            description="Alias for check_shell",
        )

    def scan_file(self, file_path: str, severity_threshold: str = "LOW") -> List[Finding]:
        """
        Scan a single workflow file for issues

        Args:
            file_path: Path to the workflow file
            severity_threshold: Minimum severity level to report

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(file_path, "r") as f:
                content = yaml.safe_load(f)

            if not content:
                return findings

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
                            severity="LOW",
                            message=f"Error executing rule {rule_id}: {str(e)}",
                            file_path=file_path,
                            remediation="This is a bug in ghast. Please report it.",
                        )
                    )

        except Exception as e:
            findings.append(
                Finding(
                    rule_id="file_error",
                    severity="MEDIUM",
                    message=f"Error parsing workflow file: {str(e)}",
                    file_path=file_path,
                    remediation="Ensure the file is valid YAML.",
                )
            )

        return findings

    def scan_directory(self, directory_path: str, severity_threshold: str = "LOW") -> List[Finding]:
        """
        Scan all workflow files in a directory

        Args:
            directory_path: Path to directory containing workflows
            severity_threshold: Minimum severity level to report

        Returns:
            List of findings
        """
        findings = []

        workflow_dir = Path(directory_path) / ".github" / "workflows"
        if not workflow_dir.exists():
            return findings

        for file_path in workflow_dir.glob("*.y*ml"):
            file_findings = self.scan_file(str(file_path), severity_threshold)
            findings.extend(file_findings)

        return findings

    def check_timeout(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for missing timeout-minutes in long jobs"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            steps = job.get("steps", [])
            if "timeout-minutes" not in job and len(steps) > 5:
                findings.append(
                    Finding(
                        rule_id="check_timeout",
                        severity="LOW",
                        message=f"Job '{job_id}' has {len(steps)} steps but no timeout-minutes set",
                        file_path=file_path,
                        remediation=f"Add 'timeout-minutes: 15' to job '{job_id}'",
                        can_fix=True,
                    )
                )

        return findings

    def check_shell(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for multiline scripts without shell specified"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            steps = job.get("steps", [])
            for step_idx, step in enumerate(steps):
                if isinstance(step, dict) and "run" in step and isinstance(step["run"], str):
                    if "\n" in step["run"] and "shell" not in step:
                        findings.append(
                            Finding(
                                rule_id="check_shell",
                                severity="LOW",
                                message=f"Multiline script in job '{job_id}' step {step_idx+1} has no shell specified",
                                file_path=file_path,
                                remediation=f"Add 'shell: bash' to this step",
                                can_fix=True,
                            )
                        )

        return findings

    def check_deprecated(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for deprecated actions"""
        findings = []
        deprecated_actions = [
            ("actions/checkout@v1", "Use actions/checkout@v3 or later"),
            ("actions/setup-python@v1", "Use actions/setup-python@v4 or later"),
            ("actions/setup-node@v1", "Use actions/setup-node@v3 or later"),
            ("actions/cache@v1", "Use actions/cache@v3 or later"),
        ]

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            steps = job.get("steps", [])
            for step_idx, step in enumerate(steps):
                if isinstance(step, dict) and "uses" in step:
                    for deprecated, recommendation in deprecated_actions:
                        if step["uses"].startswith(deprecated):
                            findings.append(
                                Finding(
                                    rule_id="check_deprecated",
                                    severity="MEDIUM",
                                    message=f"Deprecated action '{step['uses']}' in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                    remediation=recommendation,
                                    can_fix=True,
                                )
                            )

        return findings

    def check_runs_on(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for self-hosted or ambiguous runners"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            runs_on = job.get("runs-on", "")

            if not runs_on:
                findings.append(
                    Finding(
                        rule_id="check_runs_on",
                        severity="MEDIUM",
                        message=f"Missing 'runs-on' in job '{job_id}'",
                        file_path=file_path,
                        remediation="Specify a runner, e.g., 'runs-on: ubuntu-latest'",
                        can_fix=True,
                    )
                )
            elif runs_on == "self-hosted":
                findings.append(
                    Finding(
                        rule_id="check_runs_on",
                        severity="MEDIUM",
                        message=f"Job '{job_id}' uses self-hosted runner without labels",
                        file_path=file_path,
                        remediation="Add specific labels to self-hosted runners for better security isolation",
                        can_fix=False,
                    )
                )
            elif isinstance(runs_on, list) and "self-hosted" in runs_on:

                findings.append(
                    Finding(
                        rule_id="check_runs_on",
                        severity="LOW" if len(runs_on) > 1 else "MEDIUM",
                        message=f"Job '{job_id}' uses self-hosted runner",
                        file_path=file_path,
                        remediation="Consider using GitHub-hosted runners for better security isolation",
                        can_fix=False,
                    )
                )

        return findings

    def check_workflow_name(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for missing workflow name"""
        findings = []

        if "name" not in workflow:
            findings.append(
                Finding(
                    rule_id="check_workflow_name",
                    severity="LOW",
                    message="Missing workflow name (top-level 'name' field)",
                    file_path=file_path,
                    remediation=f"Add a 'name:' field at the top level of the workflow",
                    can_fix=True,
                )
            )

        return findings

    def check_continue_on_error(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for continue-on-error: true"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job.get("continue-on-error") is True:
                findings.append(
                    Finding(
                        rule_id="check_continue_on_error",
                        severity="MEDIUM",
                        message=f"Job '{job_id}' has 'continue-on-error: true'",
                        file_path=file_path,
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
                            severity="MEDIUM",
                            message=f"Step {step_idx+1} in job '{job_id}' has 'continue-on-error: true'",
                            file_path=file_path,
                            remediation="Remove 'continue-on-error' or set to false to ensure workflow fails on error",
                            can_fix=False,
                        )
                    )

        return findings

    def check_tokens(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for hardcoded tokens"""
        findings = []

        workflow_str = str(workflow)

        token_patterns = [
            (r'token\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Hardcoded token"),
            (
                r'api[_\-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
                "Hardcoded API key",
            ),
            (
                r'auth[_\-]?token\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']',
                "Hardcoded auth token",
            ),
            (r'password\s*[:=]\s*["\']([^"\']{8,})["\']', "Hardcoded password"),
            (r'secret\s*[:=]\s*["\']([^"\']{8,})["\']', "Hardcoded secret"),
            (
                r'access[_\-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
                "Hardcoded access key",
            ),
            (
                r'gh[_\-]?token\s*[:=]\s*["\']([A-Za-z0-9_\-]{30,})["\']',
                "Hardcoded GitHub token",
            ),
        ]

        for pattern, desc in token_patterns:
            matches = re.finditer(pattern, workflow_str, re.IGNORECASE)
            for match in matches:

                context_before = workflow_str[max(0, match.start() - 30) : match.start()]
                if (
                    "secrets." in context_before
                    or "${{" in context_before
                    and "secrets." in context_before
                ):
                    continue

                findings.append(
                    Finding(
                        rule_id="check_tokens",
                        severity="HIGH",
                        message=f"{desc} found in workflow file",
                        file_path=file_path,
                        remediation="Replace hardcoded tokens with secrets, e.g., ${{ secrets.GITHUB_TOKEN }}",
                        can_fix=False,
                    )
                )

        if "toJson(secrets)" in workflow_str:
            findings.append(
                Finding(
                    rule_id="check_tokens",
                    severity="CRITICAL",
                    message="Dangerous 'toJson(secrets)' usage exposes all secrets",
                    file_path=file_path,
                    remediation="Never use toJson(secrets), reference individual secrets explicitly",
                    can_fix=False,
                )
            )

        return findings

    def check_reusable_inputs(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for reusable workflows that don't properly define inputs"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            if job.get("uses") and "with" in job:

                if not job.get("inputs"):
                    findings.append(
                        Finding(
                            rule_id="check_reusable_inputs",
                            severity="MEDIUM",
                            message=f"Reusable workflow in job '{job_id}' uses 'with' without defining 'inputs'",
                            file_path=file_path,
                            remediation="Define explicit 'inputs' for reusable workflows",
                            can_fix=False,
                        )
                    )

        return findings

    def check_ppe_vulnerabilities(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for Poisoned Pipeline Execution vulnerabilities"""
        findings = []
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
                        severity="CRITICAL",
                        message=f"Poisoned Pipeline Execution vulnerability: job '{job_id}' uses {', '.join(high_risk_triggers_used)} trigger with checkout of untrusted code",
                        file_path=file_path,
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
                        severity="CRITICAL",
                        message=f"High-risk secret exposure: job '{job_id}' uses 'secrets: inherit' with {', '.join(high_risk_triggers_used)} trigger",
                        file_path=file_path,
                        remediation="Explicitly pass only required secrets to jobs, or use 'repositories' field to restrict which repos can use this workflow",
                        can_fix=False,
                        context={"triggers": list(high_risk_triggers_used)},
                    )
                )

        return findings

    def check_command_injection(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for potential command injection vulnerabilities"""
        findings = []

        dangerous_patterns = [
            (
                r"run:.*\${{.*github\.event\.(issue|comment|review).*}}",
                "Untrusted event data in shell command",
            ),
            (
                r"run:.*\${{.*github\.head_ref.*}}",
                "Untrusted head_ref in shell command",
            ),
            (
                r"run:.*\${{.*github\.event\.pull_request\.title.*}}",
                "Untrusted PR title in shell command",
            ),
            (
                r"run:.*\${{.*github\.event\.pull_request\.body.*}}",
                "Untrusted PR body in shell command",
            ),
        ]

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
            steps = job.get("steps", [])
            for step_idx, step in enumerate(steps):
                if isinstance(step, dict) and "run" in step and isinstance(step["run"], str):
                    run_command = step["run"]

                    for pattern, desc in dangerous_patterns:
                        if re.search(pattern, run_command, re.DOTALL):
                            findings.append(
                                Finding(
                                    rule_id="check_command_injection",
                                    severity="HIGH",
                                    message=f"{desc} in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                    remediation="Never use untrusted input directly in shell commands. Use input validation or environment variables with proper quoting.",
                                    can_fix=False,
                                )
                            )

                    if "${{ env." in run_command:

                        if self.strict:
                            findings.append(
                                Finding(
                                    rule_id="check_command_injection",
                                    severity="MEDIUM",
                                    message=f"Environment variable interpolation in shell command in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                    remediation="Be careful with environment variable interpolation in shell commands. Consider using proper quoting.",
                                    can_fix=False,
                                )
                            )

        return findings

    def check_env_injection(self, workflow: Dict[str, Any], file_path: str) -> List[Finding]:
        """Check for unsafe modifications to GITHUB_ENV and GITHUB_PATH"""
        findings = []

        jobs = workflow.get("jobs", {})
        for job_id, job in jobs.items():
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
                                    severity="HIGH",
                                    message=f"Modification of GITHUB_ENV after checkout in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
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
                                    severity="HIGH",
                                    message=f"Modification of GITHUB_PATH after checkout in job '{job_id}' step {step_idx+1}",
                                    file_path=file_path,
                                    remediation="Avoid modifying GITHUB_PATH after checking out untrusted code, or move path modifications before checkout.",
                                    can_fix=False,
                                )
                            )

        return findings


def scan_repository(
    repo_path: str,
    strict: bool = False,
    config: Dict[str, Any] = None,
    severity_threshold: str = "LOW",
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
    all_findings = []
    stats = {
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
