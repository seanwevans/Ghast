"""
test_file_handler_edge.py - Edge-case coverage for file handling utilities

Covers the safe_write_file failure/restore path and the
get_modified_workflows missing-directory short-circuit.
"""

import os

from ghast.utils import file_handler
from ghast.utils.file_handler import get_modified_workflows, safe_write_file


def test_safe_write_file_failure_restores_backup(tmp_path, monkeypatch, capsys):
    target = tmp_path / "file.txt"
    target.write_text("original")

    def _boom(*args, **kwargs):
        raise OSError("move failed")

    # Force the atomic move to fail after the backup has been created.
    monkeypatch.setattr(file_handler.shutil, "move", _boom)

    result = safe_write_file(str(target), "new content", create_backup=True)
    assert result is False
    # Original content is preserved via backup restore.
    assert target.read_text() == "original"
    assert "Error writing file" in capsys.readouterr().err


def test_get_modified_workflows_no_directory(tmp_path):
    # No .github/workflows directory present.
    assert get_modified_workflows(str(tmp_path)) == []
