"""
rules package for ghast - GitHub Actions Security Tool

This package contains the security rules and rule engine for finding and fixing
security issues in GitHub Actions workflows.
"""

from .base import Rule, WorkflowRule, JobRule, StepRule, TriggerRule, TokenRule
from .engine import RuleEngine, create_rule_engine
from .security import (
    PermissionsRule,
    PoisonedPipelineExecutionRule,
    CommandInjectionRule,
    EnvironmentInjectionRule,
    TokenSecurityRule,
    ActionPinningRule,
)
from .best_practices import (
    TimeoutRule,
    ShellSpecificationRule,
    WorkflowNameRule,
    DeprecatedActionsRule,
    ContinueOnErrorRule,
    ReusableWorkflowRule,
)

__all__ = [
    # Base classes
    "Rule",
    "WorkflowRule",
    "JobRule",
    "StepRule",
    "TriggerRule",
    "TokenRule",
    # Rule engine
    "RuleEngine",
    "create_rule_engine",
    # Security rules
    "PermissionsRule",
    "PoisonedPipelineExecutionRule",
    "CommandInjectionRule",
    "EnvironmentInjectionRule",
    "TokenSecurityRule",
    "ActionPinningRule",
    # Best practice rules
    "TimeoutRule",
    "ShellSpecificationRule",
    "WorkflowNameRule",
    "DeprecatedActionsRule",
    "ContinueOnErrorRule",
    "ReusableWorkflowRule",
]
