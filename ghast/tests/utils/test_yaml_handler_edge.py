"""
test_yaml_handler_edge.py - Edge-case coverage for YAML position handling

Covers non-scalar mapping keys during index building, root-scoped position
lookups, dead-root cleanup, missing-directory file discovery, and the
context-extraction error fallback.
"""

import gc
import weakref

import yaml

from ghast.utils import yaml_handler
from ghast.utils.yaml_handler import (
    PositionTrackedDict,
    _build_position_indexes,
    _cleanup_dead_roots,
    extract_line_from_file,
    find_github_workflow_files,
    find_yaml_files,
    get_position,
    load_yaml_with_positions,
)


def test_build_position_indexes_skips_non_scalar_keys():
    # A complex (sequence) mapping key produces a non-scalar key node.
    node = yaml.compose("? [a, b]\n: value\n")
    by_id, by_path = _build_position_indexes(node, {})
    # The complex key is skipped, so only the root path is recorded.
    assert by_path == {(): (1, 0)}


def test_get_position_with_root_path_and_object():
    workflow = load_yaml_with_positions("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
    assert isinstance(workflow, PositionTrackedDict)

    # Path-based lookup against an explicit root.
    line, _ = get_position(("jobs",), root=workflow)
    assert line is not None

    # Object-identity lookup against an explicit root.
    jobs = workflow["jobs"]
    obj_line, _ = get_position(jobs, root=workflow)
    assert obj_line is not None


def test_cleanup_dead_roots_removes_dead_entry():
    obj = PositionTrackedDict()
    root_id = id(obj)
    yaml_handler._root_refs[root_id] = weakref.ref(obj)
    yaml_handler._positions_by_root_id[root_id] = {}
    yaml_handler._paths_by_root_id[root_id] = {}

    del obj  # weakref now resolves to None

    _cleanup_dead_roots()
    assert root_id not in yaml_handler._root_refs
    assert root_id not in yaml_handler._positions_by_root_id


def test_weakref_callback_cleans_up_dead_root():
    # Loading registers a weakref whose callback removes the root's position
    # data once the loaded object is garbage collected.
    loaded = load_yaml_with_positions("on: push\njobs: {}\n")
    root_id = id(loaded)
    assert root_id in yaml_handler._positions_by_root_id

    del loaded
    gc.collect()
    assert root_id not in yaml_handler._positions_by_root_id
    assert root_id not in yaml_handler._root_refs


def test_find_yaml_files_missing_directory(tmp_path):
    assert find_yaml_files(str(tmp_path / "nope")) == []


def test_find_github_workflow_files_missing_directory(tmp_path):
    assert find_github_workflow_files(str(tmp_path)) == []


def test_extract_line_from_file_error_returns_empty():
    assert extract_line_from_file("/path/does/not/exist.yml", 5) == []
