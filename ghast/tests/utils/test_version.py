"""
test_version.py - Tests for version utilities
"""

import pytest

from ghast.utils.version import (
    get_version,
    get_version_info,
    parse_version,
    compare_versions,
    is_version_newer,
    get_latest_action_version,
    parse_github_ref,
    is_sha_pinned,
    is_version_pinned,
    is_unstable_reference,
    __version__,
)


def test_get_version():
    """Test retrieving version string."""
    version = get_version()
    assert isinstance(version, str)
    assert version == __version__
    assert len(version.split(".")) == 3  # Should be in format x.y.z


def test_get_version_info():
    """Test retrieving detailed version information."""
    info = get_version_info()

    assert isinstance(info, dict)
    assert "version" in info
    assert info["version"] == __version__
    assert "release_date" in info
    assert "release_year" in info

    assert isinstance(info["release_year"], int)
    assert info["release_year"] >= 2023


def test_parse_version():
    """Test parsing semantic version strings."""

    assert parse_version("1.2.3") == (1, 2, 3)
    assert parse_version("0.1.0") == (0, 1, 0)
    assert parse_version("10.20.30") == (10, 20, 30)

    with pytest.raises(ValueError):
        parse_version("1.2")  # Missing patch version

    with pytest.raises(ValueError):
        parse_version("1.2.3.4")  # Too many components

    with pytest.raises(ValueError):
        parse_version("1.2.a")  # Non-numeric patch

    with pytest.raises(ValueError):
        parse_version("v1.2.3")  # Leading 'v'


def test_compare_versions():
    """Test comparing semantic versions."""

    assert compare_versions("1.2.3", "1.2.3") == 0

    assert compare_versions("1.2.3", "1.2.4") == -1
    assert compare_versions("1.2.3", "1.3.0") == -1
    assert compare_versions("1.2.3", "2.0.0") == -1

    assert compare_versions("1.2.4", "1.2.3") == 1
    assert compare_versions("1.3.0", "1.2.3") == 1
    assert compare_versions("2.0.0", "1.9.9") == 1

    assert compare_versions("2.0.0", "1.9.9") == 1
    assert compare_versions("1.9.9", "2.0.0") == -1

    assert compare_versions("1.2.0", "1.1.9") == 1
    assert compare_versions("1.1.9", "1.2.0") == -1

    assert compare_versions("1.1.2", "1.1.1") == 1
    assert compare_versions("1.1.1", "1.1.2") == -1

    with pytest.raises(ValueError):
        compare_versions("1.2", "1.2.3")

    with pytest.raises(ValueError):
        compare_versions("1.2.3", "1.2")


def test_is_version_newer():
    """Test checking if a version is newer than another."""

    assert is_version_newer("1.2.4", "1.2.3") is True
    assert is_version_newer("1.3.0", "1.2.3") is True
    assert is_version_newer("2.0.0", "1.9.9") is True

    assert is_version_newer("1.2.3", "1.2.3") is False
    assert is_version_newer("1.2.2", "1.2.3") is False
    assert is_version_newer("1.1.9", "1.2.0") is False
    assert is_version_newer("0.9.9", "1.0.0") is False

    with pytest.raises(ValueError):
        is_version_newer("1.2", "1.2.3")

    with pytest.raises(ValueError):
        is_version_newer("1.2.3", "1.2")


def test_get_latest_action_version():
    """Test getting latest version of a GitHub Action."""

    checkout = get_latest_action_version("actions/checkout")
    assert checkout is not None
    assert isinstance(checkout, str)
    assert checkout.startswith("v")

    python = get_latest_action_version("actions/setup-python")
    assert python is not None
    assert isinstance(python, str)
    assert python.startswith("v")

    unknown = get_latest_action_version("nonexistent/action")
    assert unknown is None


def test_parse_github_ref():
    """Test parsing GitHub reference strings."""

    ref = parse_github_ref("actions/checkout@v3")
    assert ref["valid"] is True
    assert ref["owner"] == "actions"
    assert ref["repo"] == "checkout"
    assert ref["version"] == "v3"
    assert ref["version_type"] == "semver"
    assert ref["major"] == 3
    assert ref["minor"] == 0
    assert ref["patch"] == 0
    assert ref["is_major_only"] is True
    assert ref["is_pinned"] is False

    ref = parse_github_ref("actions/checkout@v3.1")
    assert ref["valid"] is True
    assert ref["version"] == "v3.1"
    assert ref["major"] == 3
    assert ref["minor"] == 1
    assert ref["patch"] == 0
    assert ref["is_major_only"] is False

    ref = parse_github_ref("actions/checkout@v3.1.2")
    assert ref["valid"] is True
    assert ref["version"] == "v3.1.2"
    assert ref["major"] == 3
    assert ref["minor"] == 1
    assert ref["patch"] == 2
    assert ref["is_major_only"] is False

    ref = parse_github_ref("actions/checkout@a12a3456b789c123d456e789f0123456a78901bc")
    assert ref["valid"] is True
    assert ref["owner"] == "actions"
    assert ref["repo"] == "checkout"
    assert ref["version"] == "a12a3456b789c123d456e789f0123456a78901bc"
    assert ref["version_type"] == "sha"
    assert ref["is_pinned"] is True

    ref = parse_github_ref("actions/checkout@main")
    assert ref["valid"] is True
    assert ref["owner"] == "actions"
    assert ref["repo"] == "checkout"
    assert ref["version"] == "main"
    assert ref["version_type"] == "branch"
    assert ref["is_pinned"] is False
    assert ref["is_unstable"] is True

    ref = parse_github_ref("actions/checkout@feature-branch")
    assert ref["valid"] is True
    assert ref["version"] == "feature-branch"
    assert ref["version_type"] == "branch"
    assert ref["is_pinned"] is False
    assert ref.get("is_unstable", False) is False

    ref = parse_github_ref("not-a-valid-reference")
    assert ref["valid"] is False


def test_is_sha_pinned():
    """Test checking if an action reference is pinned to a SHA."""

    assert is_sha_pinned("actions/checkout@a12a3456b789c123d456e789f0123456a78901bc") is True

    assert is_sha_pinned("actions/checkout@v3") is False
    assert is_sha_pinned("actions/checkout@main") is False
    assert is_sha_pinned("actions/checkout@v3.1.2") is False

    assert is_sha_pinned("not-a-valid-reference") is False


def test_is_version_pinned():
    """Test checking if an action reference is pinned to a specific version."""

    assert is_version_pinned("actions/checkout@v3.1") is True
    assert is_version_pinned("actions/checkout@v3.1.2") is True

    assert is_version_pinned("actions/checkout@v3") is False  # Major version only
    assert is_version_pinned("actions/checkout@main") is False
    assert is_version_pinned("actions/checkout@a12a3456b789c123d456e789f0123456a78901bc") is False

    assert is_version_pinned("not-a-valid-reference") is False


def test_is_unstable_reference():
    """Test checking if an action reference is to an unstable branch."""

    assert is_unstable_reference("actions/checkout@main") is True
    assert is_unstable_reference("actions/checkout@master") is True
    assert is_unstable_reference("actions/checkout@develop") is True
    assert is_unstable_reference("actions/checkout@dev") is True

    assert is_unstable_reference("actions/checkout@v3") is False
    assert is_unstable_reference("actions/checkout@v3.1.2") is False
    assert (
        is_unstable_reference("actions/checkout@a12a3456b789c123d456e789f0123456a78901bc") is False
    )
    assert is_unstable_reference("actions/checkout@feature-branch") is False

    assert is_unstable_reference("not-a-valid-reference") is False
