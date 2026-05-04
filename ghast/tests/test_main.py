"""
test_main.py - Tests for the main package functionality
"""

from pathlib import Path
from unittest.mock import Mock, patch

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
    """Test direct module execution guard without reloading the package."""
    module_code = Path("ghast/__init__.py").read_text(encoding="utf-8")

    mock_main = Mock()
    exec_globals = {"__name__": "ghast", "__package__": "ghast", "__file__": "ghast/__init__.py", "main": mock_main}
    exec(module_code, exec_globals)

    mock_main.assert_not_called()

    exec_globals_main = {"__name__": "__main__", "__package__": "ghast", "__file__": "ghast/__init__.py", "main": mock_main}
    exec(module_code, exec_globals_main)

    mock_main.assert_called_once()
