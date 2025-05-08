"""
file_handler.py - Utilities for file operations

This module provides file handling utilities for ghast, including
safe file operations, backup creation, and repository discovery.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple
import hashlib
import datetime


def is_git_repository(path: str) -> bool:
    """
    Check if a directory is a git repository

    Args:
        path: Directory path to check

    Returns:
        True if the directory contains a .git directory
    """
    git_dir = os.path.join(path, ".git")
    return os.path.isdir(git_dir)


def find_repository_root(start_path: str) -> Optional[str]:
    """
    Find the root of a git repository

    Args:
        start_path: Path to start searching from

    Returns:
        Root directory of the repository, or None if not found
    """
    current_path = os.path.abspath(start_path)

    # Handle file paths by using the parent directory
    if os.path.isfile(current_path):
        current_path = os.path.dirname(current_path)

    # Walk up the directory tree
    while True:
        if is_git_repository(current_path):
            return current_path

        parent_path = os.path.dirname(current_path)
        if parent_path == current_path:
            # Reached root directory
            return None

        current_path = parent_path


def has_github_workflows(path: str) -> bool:
    """
    Check if a directory contains GitHub workflow files

    Args:
        path: Directory path to check

    Returns:
        True if the directory contains a .github/workflows directory with YAML files
    """
    workflows_dir = os.path.join(path, ".github", "workflows")
    if not os.path.isdir(workflows_dir):
        return False

    # Check for YAML files
    yaml_files = [f for f in os.listdir(workflows_dir) if f.endswith((".yml", ".yaml"))]

    return len(yaml_files) > 0


def create_file_backup(file_path: str, suffix: str = ".bak") -> str:
    """
    Create a backup of a file

    Args:
        file_path: Path to the file to backup
        suffix: Suffix to append to the backup file name

    Returns:
        Path to the backup file

    Raises:
        FileNotFoundError: If the source file doesn't exist
    """
    backup_path = f"{file_path}{suffix}"

    # Copy the file
    shutil.copy2(file_path, backup_path)

    return backup_path


def create_timestamped_backup(file_path: str) -> str:
    """
    Create a timestamped backup of a file

    Args:
        file_path: Path to the file to backup

    Returns:
        Path to the backup file

    Raises:
        FileNotFoundError: If the source file doesn't exist
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{file_path}.{timestamp}.bak"

    # Copy the file
    shutil.copy2(file_path, backup_path)

    return backup_path


def restore_from_backup(backup_path: str, original_path: str) -> bool:
    """
    Restore a file from backup

    Args:
        backup_path: Path to the backup file
        original_path: Path to restore to

    Returns:
        True if successful, False otherwise

    Raises:
        FileNotFoundError: If the backup file doesn't exist
    """
    if not os.path.exists(backup_path):
        return False

    # Restore the file
    shutil.copy2(backup_path, original_path)

    return True


def safe_write_file(file_path: str, content: str, create_backup: bool = True) -> bool:
    """
    Safely write content to a file with backup

    Args:
        file_path: Path to the file to write
        content: Content to write
        create_backup: Whether to create a backup of the original file

    Returns:
        True if successful, False otherwise
    """
    # Create backup if requested and the file exists
    backup_path = None
    if create_backup and os.path.exists(file_path):
        backup_path = create_file_backup(file_path)

    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)

        # Write to a temporary file first
        fd, temp_path = tempfile.mkstemp(
            dir=os.path.dirname(os.path.abspath(file_path))
        )
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)

            # Replace the original file with the temporary one
            shutil.move(temp_path, file_path)
            return True
        finally:
            # Clean up the temporary file if it still exists
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    except Exception as e:
        print(f"Error writing file: {e}")

        # Restore from backup if available
        if backup_path and os.path.exists(backup_path):
            restore_from_backup(backup_path, file_path)

        return False


def compute_file_hash(file_path: str) -> str:
    """
    Compute hash of a file

    Args:
        file_path: Path to the file

    Returns:
        SHA-256 hash of the file

    Raises:
        FileNotFoundError: If the file doesn't exist
    """
    hash_obj = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)

    return hash_obj.hexdigest()


def files_are_identical(file1: str, file2: str) -> bool:
    """
    Check if two files are identical

    Args:
        file1: Path to first file
        file2: Path to second file

    Returns:
        True if files are identical, False otherwise

    Raises:
        FileNotFoundError: If either file doesn't exist
    """
    # Fast check - compare file sizes
    if os.path.getsize(file1) != os.path.getsize(file2):
        return False

    # Compute and compare hashes
    return compute_file_hash(file1) == compute_file_hash(file2)


def list_workflow_files(repo_path: str) -> List[str]:
    """
    List all GitHub Actions workflow files in a repository

    Args:
        repo_path: Path to the repository

    Returns:
        List of workflow file paths
    """
    workflows_dir = os.path.join(repo_path, ".github", "workflows")
    if not os.path.isdir(workflows_dir):
        return []

    return [
        os.path.join(workflows_dir, f)
        for f in os.listdir(workflows_dir)
        if f.endswith((".yml", ".yaml"))
    ]


def get_modified_workflows(
    repo_path: str, backup_suffix: str = ".bak"
) -> List[Tuple[str, str]]:
    """
    Get pairs of modified workflow files and their backups

    Args:
        repo_path: Path to the repository
        backup_suffix: Suffix used for backup files

    Returns:
        List of tuples (workflow_path, backup_path) for modified files
    """
    result = []
    workflows_dir = os.path.join(repo_path, ".github", "workflows")

    if not os.path.isdir(workflows_dir):
        return []

    for filename in os.listdir(workflows_dir):
        if not filename.endswith((".yml", ".yaml")):
            continue

        workflow_path = os.path.join(workflows_dir, filename)
        backup_path = f"{workflow_path}{backup_suffix}"

        if os.path.exists(backup_path) and not files_are_identical(
            workflow_path, backup_path
        ):
            result.append((workflow_path, backup_path))

    return result


def ensure_directory_exists(path: str) -> bool:
    """
    Ensure a directory exists, creating it if necessary

    Args:
        path: Directory path to ensure

    Returns:
        True if directory exists or was created, False on error
    """
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception:
        return False
