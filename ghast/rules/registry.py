"""
registry.py - The single source of truth for which rules exist

Rule identity used to be spelled three different ways: the rule's own
``rule_id`` (``token_security``), the key its config option was written under
(``check_tokens``), and the id reported on findings (``check_token_security``).
Nothing kept the three in sync, so most rules could not be configured at all
and several config keys named rules that had never existed.

Everything now derives from ``Rule.rule_id``. Legacy spellings are accepted as
explicit aliases so existing config files keep working.
"""

from typing import Any, Callable, Dict, List, Optional, Set, Tuple

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

#: Every rule ghast ships, in the order they are reported. Typed as
#: zero-argument factories because each concrete class fills in its own
#: rule_id, severity and description.
RULE_CLASSES: Tuple[Callable[[], Rule], ...] = (
    PermissionsRule,
    PoisonedPipelineExecutionRule,
    CommandInjectionRule,
    EnvironmentInjectionRule,
    TokenSecurityRule,
    ActionPinningRule,
    TimeoutRule,
    ShellSpecificationRule,
    WorkflowNameRule,
    DeprecatedActionsRule,
    ContinueOnErrorRule,
    ReusableWorkflowRule,
)

#: Config keys accepted before rule ids became canonical. Each maps to the
#: rule it was always meant to address. Several of these silently did nothing.
LEGACY_CONFIG_ALIASES: Dict[str, str] = {
    "check_timeout": "timeout",
    "check_shell": "shell_specification",
    "check_deprecated": "deprecated_actions",
    "check_workflow_name": "workflow_name",
    "check_continue_on_error": "continue_on_error",
    "check_tokens": "token_security",
    "check_reusable_inputs": "reusable_workflow_inputs",
    "check_ppe_vulnerabilities": "poisoned_pipeline_execution",
    "check_command_injection": "command_injection",
    "check_env_injection": "environment_injection",
}

#: Keys that named rules which were never implemented. Accepting them keeps
#: existing config files loading; they are reported as having no effect.
RETIRED_CONFIG_KEYS: Set[str] = {
    "check_runs_on",
    "check_inline_bash",
}


def build_default_rules() -> List[Rule]:
    """Instantiate the built-in rule set."""
    return [rule_class() for rule_class in RULE_CLASSES]


def all_rule_ids() -> List[str]:
    """Return every built-in rule id, in report order."""
    return [rule_class().rule_id for rule_class in RULE_CLASSES]


def fixable_rule_ids() -> List[str]:
    """Return the ids of rules that implement their own ``fix``.

    Determined by whether the class overrides ``Rule.fix`` rather than by a
    hand-maintained list, so a new fixer cannot be forgotten here.
    """
    return [
        rule_class().rule_id
        for rule_class in RULE_CLASSES
        if getattr(rule_class, "fix", None) is not Rule.fix
    ]


def canonical_rule_id(key: str, known_ids: Optional[Set[str]] = None) -> Optional[str]:
    """Resolve a config key or CLI argument to a rule id.

    Accepts the canonical id, a documented legacy alias, or a ``check_``
    prefixed spelling of a canonical id (findings were reported that way
    before this change, so people wrote ``--disable check_token_security``).

    Args:
        key: The user-supplied name.
        known_ids: Valid rule ids; defaults to the built-in set. Pass the
            engine's own ids so custom registered rules resolve too.

    Returns:
        The matching rule id, or None if the key names no known rule.
    """
    ids = known_ids if known_ids is not None else set(all_rule_ids())

    if key in ids:
        return key

    alias = LEGACY_CONFIG_ALIASES.get(key)
    if alias is not None and alias in ids:
        return alias

    if key.startswith("check_") and key[len("check_") :] in ids:
        return key[len("check_") :]

    return None


def build_default_config() -> Dict[str, Any]:
    """Build the default configuration from the rule registry.

    Every rule gets exactly one toggle, one severity threshold, and — if it can
    fix anything — one auto-fix entry, all keyed by its rule id. Generating
    this means a config key can never name a rule that does not exist, and a
    rule can never lack a working toggle.
    """
    rules = build_default_rules()
    fixable = set(fixable_rule_ids())

    config: Dict[str, Any] = {rule.rule_id: rule.enabled for rule in rules}
    config["severity_thresholds"] = {rule.rule_id: rule.severity for rule in rules}
    config["auto_fix"] = {
        "enabled": True,
        "rules": {rule.rule_id: rule.rule_id in fixable for rule in rules},
    }
    config["default_timeout_minutes"] = 15
    config["default_action_versions"] = {
        "actions/checkout@v1": "actions/checkout@v3",
        "actions/checkout@v2": "actions/checkout@v3",
        "actions/setup-python@v1": "actions/setup-python@v4",
        "actions/setup-python@v2": "actions/setup-python@v4",
        "actions/setup-node@v1": "actions/setup-node@v3",
        "actions/setup-node@v2": "actions/setup-node@v3",
        "actions/cache@v1": "actions/cache@v3",
        "actions/cache@v2": "actions/cache@v3",
    }
    config["report"] = {
        "include_remediation": True,
        "show_context": True,
        "color_output": True,
        "verbose": False,
        "summary": True,
    }
    return config
