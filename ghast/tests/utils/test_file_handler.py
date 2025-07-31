"""
test_file_handler.py - Tests for file handling utilities
"""

import os
import pytest
import tempfile
import shutil
from pathlib import Path

from ghast.utils.file_handler import (
    is_git_repository,
    find_repository_root,
    has_github_workflows,
    create_file_backup,
    create_timestamped_backup,
    restore_from_backup,
    safe_write_file,
    compute_file_hash,
    files_are_identical,
    list_workflow_files,
    get_modified_workflows,
    ensure_directory_exists,
)


def test_is_git_repository(temp_dir):
    """Test detection of git repositories."""

    assert is_git_repository(temp_dir) is False

    os.makedirs(os.path.join(temp_dir, ".git"))
    assert is_git_repository(temp_dir) is True


def test_find_repository_root(temp_dir):
    """Test finding the repository root."""

    root_dir = temp_dir
    os.makedirs(os.path.join(root_dir, ".git"))
    os.makedirs(os.path.join(root_dir, "subdir", "nested"))

    subdir = os.path.join(root_dir, "subdir")
    nested = os.path.join(root_dir, "subdir", "nested")

    assert find_repository_root(subdir) == root_dir
    assert find_repository_root(nested) == root_dir

    assert find_repository_root(root_dir) == root_dir

    file_path = os.path.join(nested, "file.txt")
    with open(file_path, "w") as f:
        f.write("test")

    assert find_repository_root(file_path) == root_dir

    non_repo = os.path.join(tempfile.gettempdir(), "not_a_repo")
    os.makedirs(non_repo, exist_ok=True)
    assert find_repository_root(non_repo) is None


def test_has_github_workflows(mock_repo):
    """Test detection of GitHub workflow files."""

    assert has_github_workflows(mock_repo) is True

    with tempfile.TemporaryDirectory() as temp_dir:
        assert has_github_workflows(temp_dir) is False

        os.makedirs(os.path.join(temp_dir, ".github", "workflows"))
        assert has_github_workflows(temp_dir) is False

        with open(os.path.join(temp_dir, ".github", "workflows", "not_yaml.txt"), "w") as f:
            f.write("not yaml")
        assert has_github_workflows(temp_dir) is False

        with open(os.path.join(temp_dir, ".github", "workflows", "workflow.yml"), "w") as f:
            f.write("name: Test\non: push\n")
        assert has_github_workflows(temp_dir) is True


def test_create_file_backup(temp_dir):
    """Test creating file backups."""

    file_path = os.path.join(temp_dir, "test.txt")
    with open(file_path, "w") as f:
        f.write("original content")

    backup_path = create_file_backup(file_path)

    assert os.path.exists(backup_path)
    assert backup_path.endswith(".bak")

    with open(backup_path, "r") as f:
        content = f.read()
    assert content == "original content"

    backup_path = create_file_backup(file_path, suffix=".backup")
    assert backup_path.endswith(".backup")
    assert os.path.exists(backup_path)

    with pytest.raises(FileNotFoundError):
        create_file_backup(os.path.join(temp_dir, "nonexistent.txt"))


def test_create_timestamped_backup(temp_dir):
    """Test creating timestamped backups."""

    file_path = os.path.join(temp_dir, "test.txt")
    with open(file_path, "w") as f:
        f.write("original content")

    backup_path = create_timestamped_backup(file_path)

    assert os.path.exists(backup_path)
    assert ".bak" in backup_path

    parts = backup_path.split(".")
    assert len(parts) == 3  # filename, timestamp, bak
    timestamp = parts[1]
    assert len(timestamp) > 8  # Reasonable timestamp length

    with open(backup_path, "r") as f:
        content = f.read()
    assert content == "original content"


def test_restore_from_backup(temp_dir):
    """Test restoring files from backup."""

    original_path = os.path.join(temp_dir, "test.txt")
    with open(original_path, "w") as f:
        f.write("original content")

    backup_path = create_file_backup(original_path)

    with open(original_path, "w") as f:
        f.write("modified content")

    result = restore_from_backup(backup_path, original_path)
    assert result is True

    with open(original_path, "r") as f:
        content = f.read()
    assert content == "original content"

    assert restore_from_backup(os.path.join(temp_dir, "nonexistent.bak"), original_path) is False


def test_safe_write_file(temp_dir):
    """Test safely writing content to files."""
    file_path = os.path.join(temp_dir, "test.txt")

    content = "test content"
    result = safe_write_file(file_path, content)
    assert result is True
    assert os.path.exists(file_path)

    with open(file_path, "r") as f:
        assert f.read() == content

    new_content = "updated content"
    result = safe_write_file(file_path, new_content, create_backup=True)
    assert result is True

    with open(file_path, "r") as f:
        assert f.read() == new_content

    backup_path = file_path + ".bak"
    assert os.path.exists(backup_path)
    with open(backup_path, "r") as f:
        assert f.read() == content

    nested_path = os.path.join(temp_dir, "nested", "deep", "test.txt")
    result = safe_write_file(nested_path, "nested content")
    assert result is True
    assert os.path.exists(nested_path)

    with open(nested_path, "r") as f:
        assert f.read() == "nested content"


def test_compute_file_hash(temp_dir):
    """Test computing file hashes."""

    file1 = os.path.join(temp_dir, "file1.txt")
    file2 = os.path.join(temp_dir, "file2.txt")

    with open(file1, "w") as f:
        f.write("test content")

    with open(file2, "w") as f:
        f.write("test content")

    hash1 = compute_file_hash(file1)
    hash2 = compute_file_hash(file2)

    assert hash1 == hash2
    assert isinstance(hash1, str)
    assert len(hash1) == 64  # SHA-256 is 64 hex characters

    file3 = os.path.join(temp_dir, "file3.txt")
    with open(file3, "w") as f:
        f.write("different content")

    hash3 = compute_file_hash(file3)
    assert hash3 != hash1

    with pytest.raises(FileNotFoundError):
        compute_file_hash(os.path.join(temp_dir, "nonexistent.txt"))


def test_files_are_identical(temp_dir):
    """Test comparing file contents."""

    file1 = os.path.join(temp_dir, "file1.txt")
    file2 = os.path.join(temp_dir, "file2.txt")

    with open(file1, "w") as f:
        f.write("test content")

    with open(file2, "w") as f:
        f.write("test content")

    assert files_are_identical(file1, file2) is True

    file3 = os.path.join(temp_dir, "file3.txt")
    with open(file3, "w") as f:
        f.write("different content")

    assert files_are_identical(file1, file3) is False

    assert files_are_identical(file1, file1) is True

    file4 = os.path.join(temp_dir, "file4.txt")
    with open(file4, "w") as f:
        f.write("same length entry")  # Same length as file3

    assert len("different content") == len("same length entry")
    assert files_are_identical(file3, file4) is False


def test_list_workflow_files(mock_repo):
    """Test listing workflow files in a repository."""
    workflows = list_workflow_files(mock_repo)

    assert len(workflows) > 0

    for workflow in workflows:
        assert os.path.exists(workflow)
        assert ".github/workflows" in workflow
        assert workflow.endswith((".yml", ".yaml"))

    non_existent = os.path.join(tempfile.gettempdir(), "non_existent")
    assert list_workflow_files(non_existent) == []


def test_get_modified_workflows(mock_repo, temp_dir):
    """Test detecting modified workflows."""

    test_dir = os.path.join(temp_dir, "test_repo")
    shutil.copytree(os.path.join(mock_repo, ".github"), os.path.join(test_dir, ".github"))

    assert get_modified_workflows(test_dir) == []

    workflows = list_workflow_files(test_dir)
    assert len(workflows) > 0

    test_workflow = workflows[0]

    backup_path = create_file_backup(test_workflow)

    with open(test_workflow, "a") as f:
        f.write("\n# Modified\n")

    modified = get_modified_workflows(test_dir)
    assert len(modified) > 0
    assert any(test_workflow == path for path, _ in modified)

    modified = get_modified_workflows(test_dir, backup_suffix=".backup")
    assert len(modified) == 0

    custom_backup = create_file_backup(test_workflow, suffix=".backup")
    with open(test_workflow, "a") as f:
        f.write("\n# Modified again\n")
    modified = get_modified_workflows(test_dir, backup_suffix=".backup")
    assert len(modified) > 0


def test_ensure_directory_exists(temp_dir):
    """Test ensuring a directory exists."""

    new_dir = os.path.join(temp_dir, "new_dir")
    assert not os.path.exists(new_dir)

    result = ensure_directory_exists(new_dir)
    assert result is True
    assert os.path.exists(new_dir)
    assert os.path.isdir(new_dir)

    result = ensure_directory_exists(new_dir)
    assert result is True

    nested_dir = os.path.join(temp_dir, "parent", "child", "grandchild")
    result = ensure_directory_exists(nested_dir)
    assert result is True
    assert os.path.exists(nested_dir)

    file_path = os.path.join(temp_dir, "file")
    with open(file_path, "w") as f:
        f.write("test")

    try:
        ensure_directory_exists(file_path)
    except Exception:
        pytest.fail("ensure_directory_exists raised an exception unexpectedly")
