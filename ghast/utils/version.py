"""
version.py - Version management utilities

This module provides version handling for ghast, including version information
and version comparison functionality.
"""

import re
from typing import Tuple, Optional, Dict, Any, Union
import datetime

# Version information
__version__ = "0.2.0"
__release_date__ = "2025-05-08"


def get_version() -> str:
    """
    Get ghast version

    Returns:
        Version string
    """
    return __version__


def get_version_info() -> Dict[str, Any]:
    """
    Get detailed version information

    Returns:
        Dictionary with version, release date, etc.
    """
    return {
        "version": __version__,
        "release_date": __release_date__,
        "release_year": int(__release_date__.split("-")[0]),
    }


def parse_version(version_str: str) -> Tuple[int, int, int]:
    """
    Parse a semantic version string

    Args:
        version_str: Version string in format X.Y.Z

    Returns:
        Tuple of (major, minor, patch) versions

    Raises:
        ValueError: If the version string is invalid
    """
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version_str)
    if not match:
        raise ValueError(f"Invalid version format: {version_str}")

    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def compare_versions(version1: str, version2: str) -> int:
    """
    Compare two semantic version strings

    Args:
        version1: First version string
        version2: Second version string

    Returns:
        -1 if version1 < version2, 0 if equal, 1 if version1 > version2

    Raises:
        ValueError: If either version string is invalid
    """
    v1 = parse_version(version1)
    v2 = parse_version(version2)

    if v1 < v2:
        return -1
    elif v1 > v2:
        return 1
    else:
        return 0


def is_version_newer(version: str, reference: str) -> bool:
    """
    Check if a version is newer than a reference version

    Args:
        version: Version to check
        reference: Reference version

    Returns:
        True if version is newer, False otherwise

    Raises:
        ValueError: If either version string is invalid
    """
    return compare_versions(version, reference) > 0


def get_latest_action_version(action_name: str) -> Optional[str]:
    """
    Get the latest version of a GitHub Action (placeholder implementation)

    In a real implementation, this would query the GitHub API or similar.
    For now, it returns hardcoded latest versions for common actions.

    Args:
        action_name: Name of the action (e.g., "actions/checkout")

    Returns:
        Latest version string, or None if unknown
    """
    # Hardcoded latest versions for common actions
    latest_versions = {
        "actions/checkout": "v4",
        "actions/setup-python": "v4",
        "actions/setup-node": "v3",
        "actions/cache": "v3",
        "actions/upload-artifact": "v3",
        "actions/download-artifact": "v3",
        "actions/github-script": "v6",
        "actions/setup-java": "v3",
        "actions/setup-go": "v4",
        "actions/setup-dotnet": "v3",
    }

    return latest_versions.get(action_name)


def parse_github_ref(ref: str) -> Dict[str, Any]:
    """
    Parse a GitHub reference string

    Args:
        ref: GitHub reference string (e.g., "owner/repo@v1.2.3", "owner/repo@main")

    Returns:
        Dictionary with parsed components
    """
    # Match owner/repo@version format
    match = re.match(r"^([^/]+)/([^@]+)@(.+)$", ref)
    if not match:
        return {"valid": False}

    owner = match.group(1)
    repo = match.group(2)
    version = match.group(3)

    # Check if version is a semantic version
    semver_match = re.match(r"^v?(\d+)(?:\.(\d+)(?:\.(\d+))?)?$", version)
    if semver_match:
        major = int(semver_match.group(1))
        minor = int(semver_match.group(2)) if semver_match.group(2) else 0
        patch = int(semver_match.group(3)) if semver_match.group(3) else 0

        return {
            "valid": True,
            "owner": owner,
            "repo": repo,
            "version": version,
            "version_type": "semver",
            "major": major,
            "minor": minor,
            "patch": patch,
            "is_major_only": semver_match.group(2) is None,
            "is_pinned": False,
        }

    # Check if version is a commit SHA
    sha_match = re.match(r"^[0-9a-f]{40}$", version)
    if sha_match:
        return {
            "valid": True,
            "owner": owner,
            "repo": repo,
            "version": version,
            "version_type": "sha",
            "is_pinned": True,
        }

    # Check if version is a branch name
    return {
        "valid": True,
        "owner": owner,
        "repo": repo,
        "version": version,
        "version_type": "branch",
        "is_pinned": False,
        "is_unstable": version in ["main", "master", "develop", "dev"],
    }


def is_sha_pinned(action_ref: str) -> bool:
    """
    Check if an action reference is pinned to a specific SHA

    Args:
        action_ref: Action reference string

    Returns:
        True if pinned to a SHA, False otherwise
    """
    parsed = parse_github_ref(action_ref)
    return parsed.get("valid", False) and parsed.get("version_type") == "sha"


def is_version_pinned(action_ref: str) -> bool:
    """
    Check if an action reference is pinned to a specific version (not just major)

    Args:
        action_ref: Action reference string

    Returns:
        True if pinned to a minor or patch version, False otherwise
    """
    parsed = parse_github_ref(action_ref)
    return (
        parsed.get("valid", False)
        and parsed.get("version_type") == "semver"
        and not parsed.get("is_major_only", True)
    )


def is_unstable_reference(action_ref: str) -> bool:
    """
    Check if an action reference is to an unstable branch

    Args:
        action_ref: Action reference string

    Returns:
        True if referencing an unstable branch, False otherwise
    """
    parsed = parse_github_ref(action_ref)
    return (
        parsed.get("valid", False)
        and parsed.get("version_type") == "branch"
        and parsed.get("is_unstable", False)
    )
