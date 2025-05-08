"""
test_json.py - Tests for JSON reporting functionality
"""

import json
import os
import pytest
import tempfile
from datetime import datetime

from ghast.core import Finding
from ghast.reports.json import (
    generate_json_report,
    generate_json_summary,
    save_json_report,
    finding_to_dict,
)


def test_finding_to_dict(mock_findings):
    """Test converting a Finding object to a dictionary."""
    finding = mock_findings[0]

    result = finding_to_dict(finding)
    assert isinstance(result, dict)
    assert result["rule_id"] == finding.rule_id
    assert result["severity"] == finding.severity
    assert result["message"] == finding.message
    assert result["file_path"] == finding.file_path
    assert result["can_fix"] == finding.can_fix

    finding.line_number = 42
    result = finding_to_dict(finding)
    assert result["line_number"] == 42

    finding.column = 10
    result = finding_to_dict(finding)
    assert result["column"] == 10

    finding.remediation = "Fix it"
    result = finding_to_dict(finding)
    assert result["remediation"] == "Fix it"

    finding.context = {"test": "value", "nested": {"key": "value"}}
    result = finding_to_dict(finding)
    assert result["context"] == finding.context
    assert result["context"]["test"] == "value"
    assert result["context"]["nested"]["key"] == "value"


def test_generate_json_report(mock_findings, mock_stats):
    """Test generating a JSON report."""

    report = generate_json_report(mock_findings, mock_stats)

    try:
        data = json.loads(report)
    except json.JSONDecodeError:
        pytest.fail("Generated report is not valid JSON")

    assert "ghast_version" in data
    assert "generated_at" in data
    assert "findings" in data
    assert "stats" in data

    assert len(data["findings"]) == len(mock_findings)
    for i, finding_data in enumerate(data["findings"]):
        assert finding_data["rule_id"] == mock_findings[i].rule_id
        assert finding_data["severity"] == mock_findings[i].severity
        assert finding_data["message"] == mock_findings[i].message

    assert data["stats"]["total_files"] == mock_stats["total_files"]
    assert data["stats"]["total_findings"] == mock_stats["total_findings"]

    report_no_stats = generate_json_report(mock_findings, mock_stats, include_stats=False)
    data_no_stats = json.loads(report_no_stats)
    assert "findings" in data_no_stats
    assert "stats" not in data_no_stats


def test_generate_json_summary(mock_stats):
    """Test generating a JSON summary."""
    summary = generate_json_summary(mock_stats)

    try:
        data = json.loads(summary)
    except json.JSONDecodeError:
        pytest.fail("Generated summary is not valid JSON")

    assert "ghast_version" in data
    assert "generated_at" in data
    assert "summary" in data

    assert data["summary"]["total_files"] == mock_stats["total_files"]
    assert data["summary"]["total_findings"] == mock_stats["total_findings"]

    for severity, count in mock_stats["severity_counts"].items():
        assert data["summary"]["severity_counts"][severity] == count

    for rule, count in mock_stats["rule_counts"].items():
        assert data["summary"]["rule_counts"][rule] == count

    assert "scan_duration_seconds" in data["summary"]

    stats_no_time = mock_stats.copy()
    del stats_no_time["start_time"]
    del stats_no_time["end_time"]

    summary_no_time = generate_json_summary(stats_no_time)
    data_no_time = json.loads(summary_no_time)
    assert data_no_time["summary"]["scan_duration_seconds"] is None


def test_save_json_report(mock_findings, mock_stats):
    """Test saving a JSON report to a file."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        try:

            save_json_report(mock_findings, mock_stats, tmp.name)

            assert os.path.exists(tmp.name)
            assert os.path.getsize(tmp.name) > 0

            with open(tmp.name, "r") as f:
                data = json.load(f)

            assert "findings" in data
            assert "stats" in data
            assert len(data["findings"]) == len(mock_findings)

            save_json_report(mock_findings, mock_stats, tmp.name, include_stats=False)
            with open(tmp.name, "r") as f:
                data_no_stats = json.load(f)

            assert "findings" in data_no_stats
            assert "stats" not in data_no_stats

        finally:
            os.unlink(tmp.name)


def test_json_report_formatting():
    """Test JSON report formatting and serialization."""

    finding = Finding(
        rule_id="test_rule",
        severity="HIGH",
        message="Test message",
        file_path="/path/to/file.yml",
        line_number=42,
        remediation="Fix it",
        context={
            "string": "value",
            "integer": 123,
            "float": 3.14,
            "boolean": True,
            "none": None,
            "list": [1, 2, 3],
            "dict": {"key": "value"},
            "nested": {"dict": {"key": "value"}, "list": [1, 2, {"key": "value"}]},
        },
    )

    report = generate_json_report([finding], {"total_findings": 1})

    try:
        data = json.loads(report)
    except json.JSONDecodeError:
        pytest.fail("Generated report is not valid JSON")

    context = data["findings"][0]["context"]
    assert context["string"] == "value"
    assert context["integer"] == 123
    assert context["float"] == 3.14
    assert context["boolean"] is True
    assert context["none"] is None
    assert context["list"] == [1, 2, 3]
    assert context["dict"]["key"] == "value"
    assert context["nested"]["dict"]["key"] == "value"
    assert context["nested"]["list"][2]["key"] == "value"
