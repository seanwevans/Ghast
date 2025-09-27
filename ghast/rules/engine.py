"""
engine.py - Rule engine for ghast

This module provides the core rule engine that manages and runs security rules.
"""

from typing import Any, Dict, List, Optional

from ..core import SEVERITY_LEVELS, Finding
from ..core.scanner import Severity
from .base import Rule
from .best_practices import (
    ContinueOnErrorRule,
    DeprecatedActionsRule,
    ReusableWorkflowRule,
    ShellSpecificationRule,
    TimeoutRule,
    WorkflowNameRule,
)
from .security import (
    ActionPinningRule,
    CommandInjectionRule,
    EnvironmentInjectionRule,
    PermissionsRule,
    PoisonedPipelineExecutionRule,
    TokenSecurityRule,
)


class RuleEngine:
    """Engine for managing and running GitHub Actions security rules"""

    def __init__(self, config: Optional[Dict[str, Any]] = None, strict: bool = False) -> None:
        """
        Initialize the rule engine

        Args:
            config: Configuration dictionary
            strict: Whether to use strict mode (enable additional checks)
        """
        self.config = config or {}
        self.strict = strict
        self.rules: List[Rule] = []

        self._register_default_rules()

        self._apply_config()

    def _register_default_rules(self) -> None:
        """Register the default set of rules"""

        self.rules.append(PermissionsRule())
        self.rules.append(PoisonedPipelineExecutionRule())
        self.rules.append(CommandInjectionRule())
        self.rules.append(EnvironmentInjectionRule())
        self.rules.append(TokenSecurityRule())
        self.rules.append(ActionPinningRule())

        self.rules.append(TimeoutRule())
        self.rules.append(ShellSpecificationRule())
        self.rules.append(WorkflowNameRule())
        self.rules.append(DeprecatedActionsRule())
        self.rules.append(ContinueOnErrorRule())
        self.rules.append(ReusableWorkflowRule())

    def _apply_config(self) -> None:
        """Apply configuration to rules"""
        if not self.config:
            return

        for rule in self.rules:
            rule_id = rule.rule_id
            rule_id_with_check = f"check_{rule_id}"
            short_rule_id = rule_id.replace("_rule", "").replace("_actions", "")
            short_with_check = f"check_{short_rule_id}"

            if rule_id in self.config:
                rule.enabled = bool(self.config[rule_id])
            elif rule_id_with_check in self.config:
                rule.enabled = bool(self.config[rule_id_with_check])
            elif short_rule_id in self.config:
                rule.enabled = bool(self.config[short_rule_id])
            elif short_with_check in self.config:
                rule.enabled = bool(self.config[short_with_check])

            severity_thresholds = self.config.get("severity_thresholds", {})
            if rule_id in severity_thresholds:
                value = severity_thresholds[rule_id]
            elif rule_id_with_check in severity_thresholds:
                value = severity_thresholds[rule_id_with_check]
            elif short_rule_id in severity_thresholds:
                value = severity_thresholds[short_rule_id]
            elif short_with_check in severity_thresholds:
                value = severity_thresholds[short_with_check]
            else:
                value = None

            if value is not None:
                if isinstance(value, Severity):
                    value = value.value
                rule.severity = value

    def register_rule(self, rule: Rule) -> None:
        """
        Register a custom rule

        Args:
            rule: Rule instance to register
        """
        self.rules.append(rule)

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """
        Get a rule by its ID

        Args:
            rule_id: Rule ID to look for

        Returns:
            Rule instance or None if not found
        """
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def list_rules(self) -> List[Dict[str, Any]]:
        """
        Get information about all registered rules

        Returns:
            List of rule information dictionaries
        """
        rule_info_list = []
        for rule in self.rules:
            severity = rule.severity.value if isinstance(rule.severity, Severity) else rule.severity
            rule_info_list.append(
                {
                    "id": rule.rule_id,
                    "enabled": rule.enabled,
                    "severity": severity,
                    "description": rule.description,
                    "remediation": rule.remediation,
                    "category": rule.category,
                    "can_fix": rule.can_fix,
                }
            )

        return rule_info_list

    def enable_rule(self, rule_id: str) -> bool:
        """
        Enable a rule

        Args:
            rule_id: ID of the rule to enable

        Returns:
            True if rule was found and enabled, False otherwise
        """
        rule = self.get_rule_by_id(rule_id)
        if rule:
            rule.enabled = True
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """
        Disable a rule

        Args:
            rule_id: ID of the rule to disable

        Returns:
            True if rule was found and disabled, False otherwise
        """
        rule = self.get_rule_by_id(rule_id)
        if rule:
            rule.enabled = False
            return True
        return False

    def scan_workflow(
        self,
        workflow: Dict[str, Any],
        file_path: str,
        severity_threshold: Optional[str] = None,
    ) -> List[Finding]:
        """
        Scan a workflow with all enabled rules

        Args:
            workflow: Workflow data as a dictionary
            file_path: Path to the workflow file
            severity_threshold: Minimum severity level to report

        Returns:
            List of findings
        """
        findings = []

        normalized_threshold: Optional[str] = None
        if severity_threshold is not None:
            normalized_threshold = (
                severity_threshold.value
                if isinstance(severity_threshold, Severity)
                else severity_threshold
            )

        for rule in self.rules:
            if not rule.enabled:
                continue

            rule_severity = (
                rule.severity.value if isinstance(rule.severity, Severity) else rule.severity
            )

            if normalized_threshold and (
                SEVERITY_LEVELS.index(rule_severity) < SEVERITY_LEVELS.index(normalized_threshold)
            ):
                continue

            try:
                rule_findings = rule.check(workflow, file_path)
                findings.extend(rule_findings)
            except Exception as e:
                findings.append(
                    Finding(
                        rule_id=f"rule_error.{rule.rule_id}",
                        severity="LOW",
                        message=f"Error executing rule {rule.rule_id}: {str(e)}",
                        file_path=file_path,
                        remediation="This is a bug in ghast. Please report it.",
                    )
                )

        return findings

    def fix_findings(
        self,
        workflow: Dict[str, Any],
        findings: List[Finding],
        interactive: bool = False,
    ) -> Dict[str, int]:
        """
        Apply fixes for findings

        Args:
            workflow: Workflow data as a dictionary
            findings: List of findings to fix
            interactive: Whether to prompt for each fix

        Returns:
            Dictionary with counts of fixes applied and skipped
        """
        fixes_applied = 0
        fixes_skipped = 0

        findings_by_rule: Dict[str, List[Finding]] = {}
        for finding in findings:
            if not finding.can_fix:
                fixes_skipped += 1
                continue
            if finding.rule_id not in findings_by_rule:
                findings_by_rule[finding.rule_id] = []
            findings_by_rule[finding.rule_id].append(finding)

        for rule_id, rule_findings in findings_by_rule.items():
            rule = self.get_rule_by_id(rule_id)

            if not rule or not rule.enabled:
                fixes_skipped += len(rule_findings)
                continue

            auto_fix = self.config.get("auto_fix", {}).get("rules", {}).get(rule_id, True)
            if not auto_fix:
                fixes_skipped += len(rule_findings)
                continue

            for finding in rule_findings:
                if interactive:
                    import click

                    if not click.confirm(
                        f"\nFix {finding.rule_id} issue?\n{finding.message}\nProposed fix: {finding.remediation}",
                        default=True,
                    ):
                        fixes_skipped += 1
                        continue

                try:
                    fixed = rule.fix(workflow, finding)
                    if fixed:
                        fixes_applied += 1
                    else:
                        fixes_skipped += 1
                except Exception as e:
                    print(f"Error fixing {finding.rule_id}: {e}")
                    fixes_skipped += 1

        return {"fixes_applied": fixes_applied, "fixes_skipped": fixes_skipped}


def create_rule_engine(config: Optional[Dict[str, Any]] = None, strict: bool = False) -> RuleEngine:
    """
    Create a rule engine with the specified configuration

    Args:
        config: Configuration dictionary
        strict: Whether to use strict mode

    Returns:
        Configured RuleEngine instance
    """
    return RuleEngine(config, strict)
