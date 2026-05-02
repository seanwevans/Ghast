"""
yaml_handler.py - Utilities for YAML processing

This module provides enhanced YAML handling capabilities for ghast,
including position-aware parsing and formatting preservation.
"""

import yaml
from typing import Any, Dict, List, Optional, TextIO, Sequence, Union, cast
from pathlib import Path
from yaml.nodes import Node


class LineColumnLoader(yaml.SafeLoader):
    """Custom YAML loader used for string-preserving resolution tweaks."""


Position = tuple[Optional[int], Optional[int]]
_positions_by_root_id: Dict[int, Dict[int, Position]] = {}
_paths_by_root_id: Dict[int, Dict[tuple[Union[str, int], ...], Position]] = {}


def _build_position_indexes(
    node: Node, obj: Any
) -> tuple[Dict[int, Position], Dict[tuple[Union[str, int], ...], Position]]:
    by_id: Dict[int, Position] = {}
    by_path: Dict[tuple[Union[str, int], ...], Position] = {}

    def walk(current_node: Node, current_obj: Any, path: tuple[Union[str, int], ...]) -> None:
        position = (current_node.start_mark.line + 1, current_node.start_mark.column)
        if isinstance(current_obj, (dict, list)):
            by_id[id(current_obj)] = position
        by_path[path] = position

        if isinstance(current_node, yaml.nodes.MappingNode) and isinstance(current_obj, dict):
            for key_node, value_node in current_node.value:
                if not isinstance(key_node, yaml.nodes.ScalarNode):
                    continue
                key = key_node.value
                if key in current_obj:
                    walk(value_node, current_obj[key], (*path, key))
        elif isinstance(current_node, yaml.nodes.SequenceNode) and isinstance(current_obj, list):
            for idx, item_node in enumerate(current_node.value):
                if idx < len(current_obj):
                    walk(item_node, current_obj[idx], (*path, idx))

    walk(node, obj, ())
    return by_id, by_path


def get_position(node_or_path: Any, root: Optional[Any] = None) -> Position:
    """Get (line, column) metadata for a parsed YAML object or path."""
    if root is not None:
        root_id = id(root)
        if isinstance(node_or_path, (tuple, list)):
            return _paths_by_root_id.get(root_id, {}).get(tuple(node_or_path), (None, None))
        return _positions_by_root_id.get(root_id, {}).get(id(node_or_path), (None, None))

    for positions in _positions_by_root_id.values():
        found = positions.get(id(node_or_path))
        if found is not None:
            return found
    return (None, None)


# PyYAML follows the YAML 1.1 specification which treats certain plain
# strings such as ``on``, ``off``, ``yes`` and ``no`` as booleans.  In the
# context of GitHub Actions workflows these words are frequently used as
# keys (e.g. ``on`` to specify workflow triggers).  When parsed with the
# default resolver the key ``on`` would therefore be converted to the
# boolean ``True`` which results in missing keys when later accessed via
# ``dict['on']``.  This behaviour caused `KeyError` failures in the YAML
# handler tests.
#
# To ensure these values are treated as plain strings we remove the
# implicit boolean resolver from our custom loader.  By filtering out the
# ``tag:yaml.org,2002:bool`` entries we effectively opt-in to YAML 1.2 style
# resolution for these values while still leveraging the SafeLoader for the
# rest of the parsing logic.
for first_char, resolvers in list(LineColumnLoader.yaml_implicit_resolvers.items()):
    LineColumnLoader.yaml_implicit_resolvers[first_char] = [
        (tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"
    ]


class FormattingPreservingDumper(yaml.SafeDumper):
    """Custom YAML dumper that tries to preserve formatting"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


def load_yaml_with_positions(content: str) -> Dict[str, Any]:
    """
    Load YAML content and preserve line/column positions

    Args:
        content: YAML content as string

    Returns:
        Dictionary with YAML content and position information

    Raises:
        yaml.YAMLError: If YAML parsing fails
    """
    loaded = cast(Dict[str, Any], yaml.load(content, Loader=LineColumnLoader))
    node_tree = cast(Node, yaml.compose(content, Loader=LineColumnLoader))
    by_id, by_path = _build_position_indexes(node_tree, loaded)
    _positions_by_root_id[id(loaded)] = by_id
    _paths_by_root_id[id(loaded)] = by_path
    return loaded


def load_yaml_file_with_positions(file_path: str) -> Dict[str, Any]:
    """
    Load YAML file and preserve line/column positions

    Args:
        file_path: Path to YAML file

    Returns:
        Dictionary with YAML content and position information

    Raises:
        FileNotFoundError: If file is not found
        yaml.YAMLError: If YAML parsing fails
    """
    with open(file_path, "r", encoding="utf-8") as f:
        return load_yaml_with_positions(f.read())


def clean_positions(obj: Any) -> Any:
    """
    Remove position information from YAML object before dumping

    Args:
        obj: YAML object (dict, list, etc.)

    Returns:
        Cleaned object without position information
    """
    if isinstance(obj, dict):

        return {
            k: clean_positions(v) for k, v in obj.items() if k != "__line__" and k != "__column__"
        }
    elif isinstance(obj, list):
        return [clean_positions(item) for item in obj]
    return obj


def dump_yaml(obj: Any, stream: Optional[TextIO] = None, **kwargs: Any) -> Optional[str]:
    """
    Dump YAML object with formatting preservation

    Args:
        obj: YAML object to dump
        stream: Output stream or None to return as string
        **kwargs: Additional arguments for yaml.dump

    Returns:
        YAML string if stream is None, otherwise None
    """

    kwargs.setdefault("sort_keys", False)
    kwargs.setdefault("default_flow_style", False)

    return cast(
        Optional[str],
        yaml.dump(obj, stream, Dumper=FormattingPreservingDumper, **kwargs),
    )


def find_yaml_files(directory: str, recursive: bool = True) -> List[Path]:
    """
    Find all YAML files in a directory

    Args:
        directory: Directory to search
        recursive: Whether to search recursively

    Returns:
        List of paths to YAML files
    """
    path = Path(directory)
    if not path.is_dir():
        return []

    if recursive:
        return list(path.glob("**/*.y*ml"))
    else:
        return list(path.glob("*.y*ml"))


def find_github_workflow_files(repo_path: str) -> List[Path]:
    """
    Find GitHub Actions workflow files in a repository

    Args:
        repo_path: Path to repository

    Returns:
        List of paths to workflow files
    """
    path = Path(repo_path) / ".github" / "workflows"
    if not path.is_dir():
        return []

    return list(path.glob("*.y*ml"))


def is_github_actions_workflow(yaml_content: Dict[str, Any]) -> bool:
    """
    Check if YAML content is a GitHub Actions workflow

    Args:
        yaml_content: YAML content as a dictionary

    Returns:
        True if the content seems to be a GitHub Actions workflow
    """

    if not isinstance(yaml_content, dict):
        return False

    if "on" not in yaml_content:
        return False

    if "jobs" not in yaml_content:
        return False

    return True


def extract_line_from_file(file_path: str, line_number: int, context: int = 2) -> List[str]:
    """
    Extract a line and surrounding context from a file

    Args:
        file_path: Path to file
        line_number: Line number to extract (1-based)
        context: Number of context lines before and after

    Returns:
        List of lines (including the specified line and context)
    """
    if line_number < 1:
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)

        return lines[start:end]
    except Exception:
        return []


def get_element_at_path(yaml_content: Any, path: Sequence[Union[str, int]]) -> Any:
    """
    Get element at a specific path in a YAML object

    Args:
        yaml_content: YAML content as a dictionary
        path: List of keys/indices in the path

    Returns:
        Value at the specified path, or None if not found
    """
    element = yaml_content

    for key in path:
        if isinstance(element, dict) and key in element:
            element = element[key]
        elif isinstance(element, list) and isinstance(key, int) and 0 <= key < len(element):
            element = element[key]
        else:
            return None

    return element
