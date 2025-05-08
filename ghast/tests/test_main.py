"""
test_main.py - Tests for the main package functionality
"""

import pytest
from unittest.mock import patch

import ghast


def test_version_info():
    """Test version information is accessible from the main package."""
    assert ghast.__version__ is not None
    assert isinstance(ghast.__version__, str)


def test_main_imports():
    """Test that key functions and classes are properly imported at the package level."""

    assert hasattr(ghast, "Finding")
    assert hasattr(ghast, "WorkflowScanner")
    assert hasattr(ghast, "scan_repository")
    assert hasattr(ghast, "SEVERITY_LEVELS")
    assert hasattr(ghast, "load_config")
    assert hasattr(ghast, "generate_default_config")
    assert hasattr(ghast, "save_config")
    assert hasattr(ghast, "disable_rules")
    assert hasattr(ghast, "ConfigurationError")
    assert hasattr(ghast, "fix_workflow_file")
    assert hasattr(ghast, "fix_repository")

    assert hasattr(ghast, "generate_report")
    assert hasattr(ghast, "save_report")
    assert hasattr(ghast, "print_report")
    assert hasattr(ghast, "generate_full_report")

    assert hasattr(ghast, "Rule")
    assert hasattr(ghast, "RuleEngine")
    assert hasattr(ghast, "create_rule_engine")


def test_main_function():
    """Test the main entry point function."""
    with patch("ghast.cli.cli") as mock_cli:

        ghast.main()

        mock_cli.assert_called_once()


def test_module_execution():
    """Test direct module execution."""
    with patch("ghast.main") as mock_main:
        with patch("ghast.__name__", "__main__"):

            import importlib

            importlib.reload(ghast)
            mock_main.assert_called_once()
