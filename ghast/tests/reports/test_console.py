"""
test_console.py - Tests for console output formatting
"""

import io
import os
import pytest
import sys
from unittest.mock import patch

from ghast.core import Finding
from ghast.reports.console import (
    format_finding,
    format_findings_by_file,
    format_findings_by_severity,
    format_summary,
    format_console_report,
    print_console_report,
    colorize,
    get_severity_symbol,
    SEVERITY_COLOR_NAMES,
    SEVERITY_COLORS,
)
from ghast.utils.formatter import COLORS as ANSI_COLORS


def test_get_severity_symbol():
    """Test getting symbols for severity levels."""
    assert get_severity_symbol("CRITICAL") == "🚨"
    assert get_severity_symbol("HIGH") == "❗"
    assert get_severity_symbol("MEDIUM") == "⚠️"
    assert get_severity_symbol("LOW") == "ℹ️"
    assert get_severity_symbol("INFO") == "✓"
    assert get_severity_symbol("UNKNOWN") == "✓"  # Default


def test_colorize():
    """Test colorizing text."""

    with patch.dict(os.environ, {"NO_COLOR": ""}):
        colored_text = colorize("Test", "red")
        assert colored_text != "Test"  # Should have color codes
        assert "Test" in colored_text
        assert ANSI_COLORS["red"] in colored_text
        assert ANSI_COLORS["reset"] in colored_text

    with patch.dict(os.environ, {"NO_COLOR": "1"}):
        plain_text = colorize("Test", "red")
        assert plain_text == "Test"  # Should not have color codes

    with patch.dict(os.environ, {"NO_COLOR": ""}):
        text = colorize("Test", "invalid_color")
        assert text == "Test"  # Should return original text


def test_format_finding(mock_findings):
    """Test formatting a single finding."""
    finding = mock_findings[0]  # LOW severity finding

    formatted = format_finding(finding)
    assert finding.rule_id in formatted
    assert finding.message in formatted
    assert finding.file_path in formatted
    assert finding.remediation in formatted
    assert get_severity_symbol(finding.severity) in formatted

    finding.context = {"test": "context"}
    formatted_verbose = format_finding(finding, verbose=True)
    assert "Context" in formatted_verbose
    assert "test" in formatted_verbose
    assert "context" in formatted_verbose

    formatted_no_remediation = format_finding(finding, show_remediation=False)
    assert "Remediation" not in formatted_no_remediation


def test_format_findings_by_file(mock_findings):
    """Test formatting findings grouped by file."""
    formatted = format_findings_by_file(mock_findings)

    assert "File:" in formatted

    for finding in mock_findings:
        assert finding.rule_id in formatted
        assert finding.message in formatted

    empty_formatted = format_findings_by_file([])
    assert "No issues found" in empty_formatted

    verbose_formatted = format_findings_by_file(mock_findings, verbose=True)
    assert len(verbose_formatted) > len(formatted)

    no_remediation = format_findings_by_file(mock_findings, show_remediation=False)
    assert "Remediation:" not in no_remediation


def test_format_findings_by_severity(mock_findings):
    """Test formatting findings grouped by severity."""
    formatted = format_findings_by_severity(mock_findings)

    assert "CRITICAL Severity Issues" in formatted
    assert "HIGH Severity Issues" in formatted
    assert "MEDIUM Severity Issues" in formatted
    assert "LOW Severity Issues" in formatted

    for finding in mock_findings:
        assert finding.rule_id in formatted
        assert finding.message in formatted

    empty_formatted = format_findings_by_severity([])
    assert "No issues found" in empty_formatted

    verbose_formatted = format_findings_by_severity(mock_findings, verbose=True)
    assert len(verbose_formatted) > len(formatted)

    no_remediation = format_findings_by_severity(mock_findings, show_remediation=False)
    assert "Remediation:" not in no_remediation


def test_format_findings_by_file_stable_ordering():
    """Test stable deterministic ordering for file-grouped output."""
    findings = [
        Finding("rule-z", "HIGH", "z-msg", "zeta.yml", line_number=5),
        Finding("rule-a", "HIGH", "a-msg", "alpha.yml", line_number=20),
        Finding("rule-b", "HIGH", "b-msg", "alpha.yml", line_number=None),
        Finding("rule-a", "HIGH", "a-msg-2", "alpha.yml", line_number=10),
        Finding("rule-a", "HIGH", "a-msg", "alpha.yml", line_number=10),
        Finding("rule-c", "LOW", "c-msg", "alpha.yml", line_number=1),
    ]

    formatted = format_findings_by_file(findings, show_remediation=False)

    snapshot = [line for line in formatted.splitlines() if line.strip()]
    assert snapshot == [
        "File: alpha.yml",
        "ℹ️ LOW: c-msg",
        "  Rule: rule-c",
        "  File: alpha.yml:1",
        "❗ HIGH: a-msg",
        "  Rule: rule-a",
        "  File: alpha.yml:10",
        "❗ HIGH: a-msg-2",
        "  Rule: rule-a",
        "  File: alpha.yml:10",
        "❗ HIGH: a-msg",
        "  Rule: rule-a",
        "  File: alpha.yml:20",
        "❗ HIGH: b-msg",
        "  Rule: rule-b",
        "  File: alpha.yml",
        "File: zeta.yml",
        "❗ HIGH: z-msg",
        "  Rule: rule-z",
        "  File: zeta.yml:5",
    ]


def test_format_findings_by_severity_stable_ordering():
    """Test stable deterministic ordering for severity-grouped output."""
    findings = [
        Finding("rule-z", "HIGH", "z-msg", "zeta.yml", line_number=5),
        Finding("rule-a", "HIGH", "a-msg", "alpha.yml", line_number=20),
        Finding("rule-b", "HIGH", "b-msg", "alpha.yml", line_number=None),
        Finding("rule-a", "HIGH", "a-msg-2", "alpha.yml", line_number=10),
        Finding("rule-a", "HIGH", "a-msg", "alpha.yml", line_number=10),
    ]

    formatted = format_findings_by_severity(findings, show_remediation=False)

    snapshot = [line for line in formatted.splitlines() if line.strip()]
    assert snapshot == [
        "HIGH Severity Issues (5)",
        "=" * 50,
        "❗ HIGH: z-msg",
        "  Rule: rule-z",
        "  File: zeta.yml:5",
        "❗ HIGH: a-msg",
        "  Rule: rule-a",
        "  File: alpha.yml:10",
        "❗ HIGH: a-msg-2",
        "  Rule: rule-a",
        "  File: alpha.yml:10",
        "❗ HIGH: a-msg",
        "  Rule: rule-a",
        "  File: alpha.yml:20",
        "❗ HIGH: b-msg",
        "  Rule: rule-b",
        "  File: alpha.yml",
    ]


def test_format_summary(mock_stats):
    """Test formatting summary statistics."""
    formatted = format_summary(mock_stats)

    assert "Scan Summary" in formatted

    assert f"Total files scanned: {mock_stats['total_files']}" in formatted
    assert f"Total issues found: {mock_stats['total_findings']}" in formatted

    assert "Issues by severity" in formatted
    for severity, count in mock_stats["severity_counts"].items():
        assert severity in formatted
        assert str(count) in formatted

    assert "Issues by rule" in formatted
    for rule, count in mock_stats["rule_counts"].items():
        assert rule in formatted
        assert str(count) in formatted

    assert "Scan duration" in formatted
    assert "seconds" in formatted


def test_format_console_report(mock_findings, mock_stats):
    """Test formatting a complete console report."""

    formatted = format_console_report(mock_findings, mock_stats)
    assert "File:" in formatted
    assert "Scan Summary" in formatted

    formatted_by_severity = format_console_report(mock_findings, mock_stats, group_by_severity=True)
    assert "Severity Issues" in formatted_by_severity
    assert "Scan Summary" in formatted_by_severity

    verbose_formatted = format_console_report(mock_findings, mock_stats, verbose=True)
    assert len(verbose_formatted) > len(formatted)

    no_remediation = format_console_report(mock_findings, mock_stats, show_remediation=False)
    assert "Remediation:" not in no_remediation

    no_summary = format_console_report(mock_findings, mock_stats, show_summary=False)
    assert "Scan Summary" not in no_summary


def test_print_console_report(mock_findings, mock_stats, capsys):
    """Test printing a console report to stdout."""

    print_console_report(mock_findings, mock_stats)
    captured = capsys.readouterr()
    assert captured.out
    assert "Scan Summary" in captured.out

    custom_stream = io.StringIO()
    print_console_report(mock_findings, mock_stats, output_stream=custom_stream)
    custom_stream.seek(0)
    content = custom_stream.read()
    assert "Scan Summary" in content

    print_console_report(
        mock_findings, mock_stats, group_by_severity=True, verbose=True, show_remediation=False
    )
    captured = capsys.readouterr()
    assert "Severity Issues" in captured.out
    assert "Remediation:" not in captured.out
