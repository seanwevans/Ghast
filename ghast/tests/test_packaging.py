"""Tests guarding the distribution metadata.

The failure these protect against is invisible to the rest of the suite: every
other test runs against the source tree, so a wheel that omits subpackages
still passes everything while being completely unimportable once installed.
"""

import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    tomllib = pytest.importorskip("tomli")

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"

SUBPACKAGES = ["core", "reports", "rules", "utils"]


@pytest.fixture(scope="module")
def pyproject():
    with open(PYPROJECT, "rb") as handle:
        return tomllib.load(handle)


def test_packages_are_discovered_not_hardcoded(pyproject):
    """A literal ``packages = ["ghast"]`` silently drops every subpackage."""
    setuptools = pyproject["tool"]["setuptools"]

    assert "packages" not in setuptools or not isinstance(
        setuptools.get("packages"), list
    ), "use [tool.setuptools.packages.find] so subpackages are included"

    find = setuptools["packages"]["find"]
    assert find["include"] == ["ghast*"]
    assert find["exclude"] == ["ghast.tests*"]


def test_every_subpackage_is_importable():
    for name in SUBPACKAGES:
        __import__(f"ghast.{name}")


def test_requires_python_matches_the_syntax_actually_used(pyproject):
    """yaml_handler uses PEP 585 generics at module scope, which need 3.10+."""
    assert pyproject["project"]["requires-python"] == ">=3.10"


def test_classifiers_do_not_claim_untested_versions(pyproject):
    classifiers = pyproject["project"]["classifiers"]
    versions = [
        c.rsplit(" :: ", 1)[1]
        for c in classifiers
        if c.startswith("Programming Language :: Python :: ") and "." in c
    ]
    for version in versions:
        major, minor = (int(part) for part in version.split("."))
        assert (major, minor) >= (3, 10), f"classifier claims unsupported {version}"


def test_running_interpreter_satisfies_declared_floor():
    assert sys.version_info >= (3, 10)
