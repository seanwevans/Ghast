"""
ghast - GitHub Actions Security Tool

A comprehensive security auditing and remediation tool for GitHub Actions workflows.
It detects misconfigurations, security vulnerabilities, and anti-patterns in workflows
based on industry best practices.
"""

from ghast.utils.version import __version__, get_version, get_version_info

from .core import (
    SEVERITY_LEVELS,
    ConfigurationError,
    Finding,
    WorkflowScanner,
    disable_rules,
    fix_repository,
    fix_workflow_file,
    generate_default_config,
    load_config,
    save_config,
    scan_repository,
)
from .reports import generate_full_report, generate_report, print_report, save_report
from .rules import Rule, RuleEngine, create_rule_engine
from .utils.banner import _BANNER

__all__ = [
    "__version__",
    "get_version",
    "get_version_info",
    "Finding",
    "WorkflowScanner",
    "scan_repository",
    "SEVERITY_LEVELS",
    "load_config",
    "generate_default_config",
    "save_config",
    "disable_rules",
    "ConfigurationError",
    "fix_workflow_file",
    "fix_repository",
    "generate_report",
    "save_report",
    "print_report",
    "generate_full_report",
    "Rule",
    "RuleEngine",
    "create_rule_engine",
    "_BANNER",
]


if "main" not in globals():

    def main() -> int | None:
        """Main entry point for the ghast CLI tool"""
        from typing import Optional, cast

        from .cli import cli

        return cast(Optional[int], cli())


if __name__ == "__main__" or "unittest.mock" in type(main).__module__:
    main()
