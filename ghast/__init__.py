"""
ghast - GitHub Actions Security Tool

A comprehensive security auditing and remediation tool for GitHub Actions workflows.
It detects misconfigurations, security vulnerabilities, and anti-patterns in workflows
based on industry best practices.
"""

# Import version information
from .utils.version import __version__, get_version, get_version_info

# Import core functionality
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

# Import reporting functionality
from .reports import generate_report, save_report, print_report, generate_full_report

# Import rule engine
from .rules import Rule, RuleEngine, create_rule_engine

# Banner ASCII art
from .banner import _BANNER

# Public API
__all__ = [
    # Version information
    "__version__",
    "get_version",
    "get_version_info",
    # Core functionality
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
    # Reporting
    "generate_report",
    "save_report",
    "print_report",
    "generate_full_report",
    # Rules
    "Rule",
    "RuleEngine",
    "create_rule_engine",
    # Banner
    "_BANNER",
]

# Main function for CLI usage
def main():
    """Main entry point for the ghast CLI tool"""
    import sys
    from .cli import cli

    # Run the CLI with the provided arguments
    sys.exit(cli())


if __name__ == "__main__":
    main()
