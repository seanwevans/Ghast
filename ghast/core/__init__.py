"""
core package for GitHub Actions Security Tool

This package contains the core scanning and analysis functionality.
"""

from .scanner import WorkflowScanner, Finding, scan_repository, SEVERITY_LEVELS
from .config import (
    load_config,
    generate_default_config,
    save_config,
    disable_rules,
    ConfigurationError,
)
from .fixer import fix_workflow_file, fix_repository, Fixer

__all__ = [
    "WorkflowScanner",
    "Finding",
    "scan_repository",
    "SEVERITY_LEVELS",
    "load_config",
    "generate_default_config",
    "save_config",
    "disable_rules",
    "ConfigurationError",
    "fix_workflow_file",
    "fix_repository",
    "Fixer",
]
