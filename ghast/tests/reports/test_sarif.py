"""
test_sarif.py - Tests for SARIF reporting functionality
"""

import json
import os
import pytest
import tempfile
from pathlib import Path

from ghast.core import Finding
from ghast.reports.sarif import (
    generate_sarif_report,
    save_sarif_report,
    generate_sarif_suppression_file,
    severity_to_sarif_level,
    rule_to_sarif_rule,
    finding_to_sarif_result,
    SARIF_VERSION,
    SARIF_SCHEMA,
    GITHUB_SEVERITY_LEVELS,
    SECURITY_SEVERITY_SCORES,
)


def test_severity_to_sarif_level():
    """Test converting ghast severity levels to SARIF levels."""
    assert severity_to_sarif_level("CRITICAL") == "error"
    assert severity_to_sarif_level("HIGH") == "error"
    assert severity_to_sarif_level("MEDIUM") == "warning"
    assert severity_to_sarif_level("LOW") == "note"
    assert severity_to_sarif_level("INFO") == "note"
    assert severity_to_sarif_level("UNKNOWN") == "warning"  # Default


def test_rule_to_sarif_rule():
    """Test converting a ghast rule to a SARIF rule."""

    rule = rule_to_sarif_rule("test_rule", "HIGH", "Test description", "Test help text")

    assert rule["id"] == "test_rule"
    assert rule["shortDescription"]["text"] == "Test description"
    assert rule["helpText"]["text"] == "Test help text"
    assert rule["fullDescription"]["text"] == "Test description"
    assert rule["properties"]["security-severity"] == str(SECURITY_SEVERITY_SCORES["HIGH"])

    rule_no_help = rule_to_sarif_rule("test_rule", "HIGH", "Test description")
    assert "helpText" not in rule_no_help

    rule_no_desc = rule_to_sarif_rule("test_rule", "HIGH")
    assert rule_no_desc["shortDescription"]["text"] == "Rule test_rule"
    assert "fullDescription" not in rule_no_desc


def test_finding_to_sarif_result(mock_findings):
    """Test converting a ghast finding to a SARIF result."""
    finding = mock_findings[0]

    result = finding_to_sarif_result(finding)

    assert result["ruleId"] == finding.rule_id
    assert result["level"] == severity_to_sarif_level(finding.severity)
    assert result["message"]["text"] == finding.message
    assert (
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == finding.file_path
    )

    finding.line_number = 42
    result = finding_to_sarif_result(finding)
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 42

    finding.column = 10
    result = finding_to_sarif_result(finding)
    assert result["locations"][0]["physicalLocation"]["region"]["startColumn"] == 10

    finding.remediation = "Fix it"
    result = finding_to_sarif_result(finding)
    assert result["fixes"][0]["description"]["text"] == "Fix it"

    finding.context = {"test": "value"}
    result = finding_to_sarif_result(finding)
    assert result["properties"]["context"]["test"] == "value"

    repo_root = "/path/to"
    finding.file_path = "/path/to/file.yml"
    result = finding_to_sarif_result(finding, repo_root)
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "file.yml"


def test_generate_sarif_report(mock_findings, mock_stats):
    """Test generating a SARIF report."""

    report = generate_sarif_report(mock_findings, mock_stats)

    try:
        data = json.loads(report)
    except json.JSONDecodeError:
        pytest.fail("Generated report is not valid JSON")

    assert data["$schema"] == SARIF_SCHEMA
    assert data["version"] == SARIF_VERSION
    assert "runs" in data
    assert len(data["runs"]) == 1

    run = data["runs"][0]
    assert "tool" in run
    assert "results" in run
    assert "properties" in run

    assert "driver" in run["tool"]
    assert "name" in run["tool"]["driver"]
    assert "version" in run["tool"]["driver"]
    assert "informationUri" in run["tool"]["driver"]
    assert "rules" in run["tool"]["driver"]

    assert len(run["results"]) == len(mock_findings)

    assert run["properties"]["metrics"]["total_findings"] == mock_stats["total_findings"]
    assert run["properties"]["metrics"]["total_files"] == mock_stats["total_files"]

    rules = run["tool"]["driver"]["rules"]
    rule_ids = {rule["id"] for rule in rules}
    finding_rule_ids = {finding.rule_id for finding in mock_findings}
    assert rule_ids == finding_rule_ids

    assert "invocations" in run
    assert run["invocations"][0]["executionSuccessful"] is True
    assert "startTimeUtc" in run["invocations"][0]
    assert "endTimeUtc" in run["invocations"][0]

    report_with_root = generate_sarif_report(mock_findings, mock_stats, repo_root="/path/to/repo")
    data_with_root = json.loads(report_with_root)
    assert "$schema" in data_with_root

    report_custom = generate_sarif_report(
        mock_findings, mock_stats, tool_name="custom_tool", tool_version="1.2.3"
    )
    data_custom = json.loads(report_custom)
    assert data_custom["runs"][0]["tool"]["driver"]["name"] == "custom_tool"
    assert data_custom["runs"][0]["tool"]["driver"]["version"] == "1.2.3"


def test_save_sarif_report(mock_findings, mock_stats):
    """Test saving a SARIF report to a file."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        try:

            save_sarif_report(mock_findings, mock_stats, tmp.name)

            assert os.path.exists(tmp.name)
            assert os.path.getsize(tmp.name) > 0

            with open(tmp.name, "r") as f:
                data = json.load(f)

            assert "$schema" in data
            assert "version" in data
            assert "runs" in data

            save_sarif_report(
                mock_findings, mock_stats, tmp.name, tool_name="custom_tool", tool_version="1.2.3"
            )

            with open(tmp.name, "r") as f:
                data_custom = json.load(f)

            assert data_custom["runs"][0]["tool"]["driver"]["name"] == "custom_tool"
            assert data_custom["runs"][0]["tool"]["driver"]["version"] == "1.2.3"

        finally:
            os.unlink(tmp.name)


def test_generate_sarif_suppression_file(mock_findings):
    """Test generating a SARIF suppressions file."""
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        try:

            generate_sarif_suppression_file(mock_findings, tmp.name)

            assert os.path.exists(tmp.name)
            assert os.path.getsize(tmp.name) > 0

            with open(tmp.name, "r") as f:
                data = json.load(f)

            assert "$schema" in data
            assert "version" in data
            assert "runs" in data
            assert len(data["runs"]) == 1

            run = data["runs"][0]
            assert "tool" in run
            assert "suppressions" in run

            suppressions = run["suppressions"]
            assert len(suppressions) == len(mock_findings)

            for i, suppression in enumerate(suppressions):
                assert "guid" in suppression
                assert "kind" in suppression
                assert suppression["kind"] == "inSource"
                assert "justification" in suppression
                assert "location" in suppression
                assert "properties" in suppression
                assert suppression["properties"]["rule_id"] == mock_findings[i].rule_id
                assert "suppressed_at" in suppression["properties"]

                assert "physicalLocation" in suppression["location"]
                assert "artifactLocation" in suppression["location"]["physicalLocation"]
                assert (
                    suppression["location"]["physicalLocation"]["artifactLocation"]["uri"]
                    == mock_findings[i].file_path
                )

                if mock_findings[i].line_number is not None:
                    assert "region" in suppression["location"]["physicalLocation"]
                    assert (
                        suppression["location"]["physicalLocation"]["region"]["startLine"]
                        == mock_findings[i].line_number
                    )

        finally:
            os.unlink(tmp.name)


def test_sarif_validation(mock_findings, mock_stats):
    """Test that generated SARIF reports are valid according to the schema."""

    report = generate_sarif_report(mock_findings, mock_stats)
    data = json.loads(report)

    assert "$schema" in data
    assert "version" in data
    assert "runs" in data

    run = data["runs"][0]
    assert "tool" in run
    assert "results" in run

    assert "driver" in run["tool"]
    driver = run["tool"]["driver"]
    assert "name" in driver
    assert "rules" in driver

    for rule in driver["rules"]:
        assert "id" in rule
        assert "shortDescription" in rule
        assert "text" in rule["shortDescription"]

    for result in run["results"]:
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "text" in result["message"]
        assert "locations" in result
        assert len(result["locations"]) > 0

        location = result["locations"][0]
        assert "physicalLocation" in location
        assert "artifactLocation" in location["physicalLocation"]
        assert "uri" in location["physicalLocation"]["artifactLocation"]
