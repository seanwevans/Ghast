"""
test_yaml_handler.py - Tests for YAML handling utilities
"""

import os
import pytest
import yaml
import tempfile
from pathlib import Path

from ghast.utils.yaml_handler import (
    load_yaml_with_positions,
    load_yaml_file_with_positions,
    clean_positions,
    dump_yaml,
    find_yaml_files,
    find_github_workflow_files,
    is_github_actions_workflow,
    extract_line_from_file,
    get_element_at_path,
)


def test_load_yaml_with_positions():
    """Test loading YAML with position tracking."""
    yaml_content = """
name: Test Workflow
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run tests
        run: pytest
"""

    result = load_yaml_with_positions(yaml_content)

    assert result["name"] == "Test Workflow"
    assert result["on"] == "push"
    assert "jobs" in result
    assert "build" in result["jobs"]

    assert "__line__" in result
    assert "__column__" in result
    assert "__line__" in result["jobs"]
    assert "__column__" in result["jobs"]
    assert "__line__" in result["jobs"]["build"]
    assert "__column__" in result["jobs"]["build"]


def test_load_yaml_file_with_positions(temp_dir):
    """Test loading a YAML file with position tracking."""

    yaml_file = os.path.join(temp_dir, "test.yml")
    yaml_content = """
name: Test Workflow
on: push
jobs:
  build:
    runs-on: ubuntu-latest
"""

    with open(yaml_file, "w") as f:
        f.write(yaml_content)

    result = load_yaml_file_with_positions(yaml_file)

    assert result["name"] == "Test Workflow"
    assert result["on"] == "push"
    assert "jobs" in result
    assert "build" in result["jobs"]

    assert "__line__" in result
    assert "__column__" in result
    assert "__line__" in result["jobs"]
    assert "__column__" in result["jobs"]


def test_clean_positions():
    """Test cleaning position information from YAML objects."""

    obj = {
        "name": "Test",
        "__line__": 1,
        "__column__": 0,
        "nested": {"key": "value", "__line__": 2, "__column__": 2},
        "list": [{"item": "value", "__line__": 3, "__column__": 4}],
    }

    cleaned = clean_positions(obj)

    assert "__line__" not in cleaned
    assert "__column__" not in cleaned
    assert "__line__" not in cleaned["nested"]
    assert "__column__" not in cleaned["nested"]
    assert "__line__" not in cleaned["list"][0]
    assert "__column__" not in cleaned["list"][0]

    assert cleaned["name"] == "Test"
    assert cleaned["nested"]["key"] == "value"
    assert cleaned["list"][0]["item"] == "value"


def test_dump_yaml():
    """Test dumping YAML with formatting preservation."""

    obj = {
        "name": "Test Workflow",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [{"uses": "actions/checkout@v3"}, {"run": "pytest"}],
            }
        },
        "__line__": 1,  # Should be removed in output
        "__column__": 0,  # Should be removed in output
    }

    result = dump_yaml(obj)

    parsed = yaml.safe_load(result)
    assert parsed["name"] == "Test Workflow"
    assert parsed["on"] == "push"
    assert "jobs" in parsed

    assert "__line__" not in parsed
    assert "__column__" not in parsed

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        dump_yaml(obj, f)
        f.close()

        with open(f.name, "r") as f2:
            content = f2.read()

        os.unlink(f.name)

    parsed = yaml.safe_load(content)
    assert parsed["name"] == "Test Workflow"
    assert "__line__" not in parsed


def test_find_yaml_files(temp_dir):
    """Test finding YAML files in a directory."""

    os.makedirs(os.path.join(temp_dir, "subdir"), exist_ok=True)

    with open(os.path.join(temp_dir, "file1.yml"), "w") as f:
        f.write("key: value")

    with open(os.path.join(temp_dir, "file2.yaml"), "w") as f:
        f.write("key: value")

    with open(os.path.join(temp_dir, "notayaml.txt"), "w") as f:
        f.write("not yaml")

    with open(os.path.join(temp_dir, "subdir", "file3.yml"), "w") as f:
        f.write("key: value")

    files = find_yaml_files(temp_dir)
    assert len(files) == 3
    assert any(f.name == "file1.yml" for f in files)
    assert any(f.name == "file2.yaml" for f in files)
    assert any(f.name == "file3.yml" for f in files)

    files = find_yaml_files(temp_dir, recursive=False)
    assert len(files) == 2
    assert any(f.name == "file1.yml" for f in files)
    assert any(f.name == "file2.yaml" for f in files)
    assert not any(f.name == "file3.yml" for f in files)


def test_find_github_workflow_files(mock_repo):
    """Test finding GitHub workflow files in a repository."""

    files = find_github_workflow_files(mock_repo)
    assert len(files) > 0

    for file in files:
        assert ".github/workflows" in str(file)
        assert file.suffix in [".yml", ".yaml"]


def test_is_github_actions_workflow():
    """Test detection of GitHub Actions workflow content."""

    valid_workflow = {
        "name": "Test",
        "on": "push",
        "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo 'Hello'"}]}},
    }

    assert is_github_actions_workflow(valid_workflow) is True

    invalid_workflow1 = {
        "name": "Test",
        "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo 'Hello'"}]}},
    }

    assert is_github_actions_workflow(invalid_workflow1) is False

    invalid_workflow2 = {"name": "Test", "on": "push", "steps": [{"run": "echo 'Hello'"}]}

    assert is_github_actions_workflow(invalid_workflow2) is False

    assert is_github_actions_workflow("not a dict") is False
    assert is_github_actions_workflow(None) is False
    assert is_github_actions_workflow([]) is False


def test_extract_line_from_file(temp_dir):
    """Test extracting a line with context from a file."""

    file_path = os.path.join(temp_dir, "test.txt")
    content = "\n".join([f"Line {i}" for i in range(1, 11)])

    with open(file_path, "w") as f:
        f.write(content)

    lines = extract_line_from_file(file_path, 5, context=2)
    assert len(lines) == 5  # Line 5 + 2 before + 2 after
    assert lines[0].strip() == "Line 3"
    assert lines[1].strip() == "Line 4"
    assert lines[2].strip() == "Line 5"
    assert lines[3].strip() == "Line 6"
    assert lines[4].strip() == "Line 7"

    lines = extract_line_from_file(file_path, 1, context=2)
    assert len(lines) == 3  # Line 1 + 0 before + 2 after
    assert lines[0].strip() == "Line 1"
    assert lines[1].strip() == "Line 2"
    assert lines[2].strip() == "Line 3"

    lines = extract_line_from_file(file_path, 10, context=2)
    assert len(lines) == 3  # Line 10 + 2 before + 0 after
    assert lines[0].strip() == "Line 8"
    assert lines[1].strip() == "Line 9"
    assert lines[2].strip() == "Line 10"

    lines = extract_line_from_file(file_path, 0, context=2)
    assert len(lines) == 0

    lines = extract_line_from_file(file_path, 100, context=2)
    assert len(lines) == 0


def test_get_element_at_path():
    """Test getting an element at a specific path in a YAML object."""

    obj = {"name": "Test", "jobs": {"build": {"steps": [{"run": "step1"}, {"run": "step2"}]}}}

    assert get_element_at_path(obj, ["name"]) == "Test"
    assert get_element_at_path(obj, ["jobs", "build"]) == {
        "steps": [{"run": "step1"}, {"run": "step2"}]
    }
    assert get_element_at_path(obj, ["jobs", "build", "steps", 0]) == {"run": "step1"}
    assert get_element_at_path(obj, ["jobs", "build", "steps", 0, "run"]) == "step1"

    assert get_element_at_path(obj, ["nonexistent"]) is None
    assert get_element_at_path(obj, ["jobs", "nonexistent"]) is None
    assert get_element_at_path(obj, ["jobs", "build", "steps", 100]) is None
