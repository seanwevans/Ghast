"""Tests for the release pipeline.

Publishing used a long-lived `PYPI_API_TOKEN`: a credential with upload
rights that never expires on its own and that nobody schedules a rotation
for. These assert it is gone, and that the OIDC path replacing it is wired
up correctly, since none of it is exercised until a tag is pushed.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


CI_WORKFLOW = ROOT / ".github" / "workflows" / "python-app.yml"


@pytest.fixture(scope="module")
def publish_job():
    with open(CI_WORKFLOW) as handle:
        return yaml.safe_load(handle)["jobs"]["build-and-publish"]


def test_publish_uses_trusted_publishing(publish_job):
    """No `password:` means the action authenticates over OIDC."""
    step = next(s for s in publish_job["steps"] if "pypi-publish" in s.get("uses", ""))

    assert "password" not in step.get("with", {})
    assert "user" not in step.get("with", {})


def test_publish_requests_an_oidc_token(publish_job):
    assert publish_job["permissions"]["id-token"] == "write"


def test_publish_runs_in_a_named_environment(publish_job):
    """Gives the release somewhere to require approval or restrict tags."""
    assert publish_job["environment"]["name"] == "pypi"


def test_no_workflow_reads_a_long_lived_pypi_token():
    """The credential worth removing is the one that never expires.

    Matches the secret *reference* rather than the name, so a comment
    explaining why the token was dropped does not trip the guard.
    """
    import re

    reference = re.compile(r"secrets\s*\.\s*PYPI_API_TOKEN")

    for path in sorted((ROOT / ".github" / "workflows").glob("*.y*ml")):
        assert not reference.search(path.read_text()), f"{path.name} still uses a static token"


def test_publish_validates_metadata_before_uploading():
    """A malformed long_description fails on PyPI, after the tag exists."""
    with open(CI_WORKFLOW) as handle:
        text = handle.read()

    assert "twine check --strict" in text
