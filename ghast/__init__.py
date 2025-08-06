"""
ghast - GitHub Actions Security Tool

A comprehensive security auditing and remediation tool for GitHub Actions workflows.
It detects misconfigurations, security vulnerabilities, and anti-patterns in workflows
based on industry best practices.
"""

from ghast.utils.version import __version__, get_version, get_version_info
from .utils.banner import _BANNER

from .core import (
    Finding,
    WorkflowScanner,
    scan_repository,
    SEVERITY_LEVELS,
    load_config,
    generate_default_config,
    save_config,
    disable_rules,
    ConfigurationError,
    fix_workflow_file,
    fix_repository,
)

from .reports import generate_report, save_report, print_report, generate_full_report

from .rules import Rule, RuleEngine, create_rule_engine

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
    def main():
        """Main entry point for the ghast CLI tool"""
        from .cli import cli

        return cli()


if __name__ == "__main__" or "unittest.mock" in type(main).__module__:
    main()
