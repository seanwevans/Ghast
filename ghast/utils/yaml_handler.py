"""
yaml_handler.py - Utilities for YAML processing

This module provides enhanced YAML handling capabilities for ghast,
including position-aware parsing and formatting preservation.
"""

import yaml
from typing import Any, Dict, List, Optional, TextIO, Sequence, Union, cast
from pathlib import Path
from yaml.nodes import MappingNode, Node


class LineColumnLoader(yaml.SafeLoader):
    """Custom YAML loader that tracks line and column information"""

    def __init__(self, stream: TextIO | str) -> None:
        super().__init__(stream)

    def compose_node(self, parent: Any, index: Any) -> Node:
        """Add line/column information to nodes"""
        node = cast(Node, super().compose_node(parent, index))
        setattr(node, "__line__", self.line + 1)
        setattr(node, "__column__", self.column)
        return node

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> Dict[Any, Any]:
        """Add line/column information to dictionaries"""
        mapping = cast(Dict[Any, Any], super().construct_mapping(node, deep=deep))
        mapping["__line__"] = getattr(node, "__line__", None)
        mapping["__column__"] = getattr(node, "__column__", None)
        return mapping


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
    return cast(Dict[str, Any], yaml.load(content, Loader=LineColumnLoader))


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
    with open(file_path, "r") as f:
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

    cleaned_obj = clean_positions(obj)

    kwargs.setdefault("sort_keys", False)
    kwargs.setdefault("default_flow_style", False)

    return cast(
        Optional[str],
        yaml.dump(cleaned_obj, stream, Dumper=FormattingPreservingDumper, **kwargs),
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
        with open(file_path, "r") as f:
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
