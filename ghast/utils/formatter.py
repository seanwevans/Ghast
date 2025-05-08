"""
formatter.py - Output formatting utilities

This module provides consistent formatting for console output,
including color coding, indentation, and summary statistics.
"""

import os
import re
from typing import List, Dict, Any, Optional, TextIO, Union
import sys
import shutil
import platform

# ANSI color codes
COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "underline": "\033[4m",
    "black": "\033[30m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_black": "\033[90m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_blue": "\033[94m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
    "bright_white": "\033[97m",
    "bg_black": "\033[40m",
    "bg_red": "\033[41m",
    "bg_green": "\033[42m",
    "bg_yellow": "\033[43m",
    "bg_blue": "\033[44m",
    "bg_magenta": "\033[45m",
    "bg_cyan": "\033[46m",
    "bg_white": "\033[47m",
}

# Severity colors
SEVERITY_COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "green",
}

# Severity symbols
SEVERITY_SYMBOLS = {
    "CRITICAL": "🚨",
    "HIGH": "❗",
    "MEDIUM": "⚠️",
    "LOW": "ℹ️",
    "INFO": "✓",
}


def supports_color() -> bool:
    """
    Check if the terminal supports color output

    Returns:
        True if color is supported, False otherwise
    """
    # Return False if NO_COLOR environment variable is set
    if os.environ.get("NO_COLOR") is not None:
        return False

    # Return False if explicitly disabled
    if os.environ.get("GHAST_NO_COLOR") is not None:
        return False

    # Check platform-specific conditions
    plat = platform.system()
    if plat == "Windows":
        # Windows 10 with VT support or ANSICON
        return (
            os.environ.get("ANSICON") is not None
            or os.environ.get("WT_SESSION") is not None
            or os.environ.get("ConEmuANSI") == "ON"
            or os.environ.get("TERM_PROGRAM") is not None
        )
    else:
        # Unix-like platforms with a TTY
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def colorize(text: str, color: str) -> str:
    """
    Apply color to text if supported

    Args:
        text: Text to colorize
        color: Color name from COLORS dict

    Returns:
        Colorized text or original text if color not supported
    """
    if not supports_color() or color not in COLORS:
        return text

    return f"{COLORS[color]}{text}{COLORS['reset']}"


def get_console_width() -> int:
    """
    Get width of the console

    Returns:
        Width in characters
    """
    try:
        columns, _ = shutil.get_terminal_size()
        return columns
    except Exception:
        return 80  # Default width


def format_severity(severity: str) -> str:
    """
    Format a severity level with color and symbol

    Args:
        severity: Severity level string

    Returns:
        Formatted severity string
    """
    symbol = SEVERITY_SYMBOLS.get(severity, "•")
    color = SEVERITY_COLORS.get(severity, "reset")

    return f"{symbol} {colorize(severity, color)}"


def format_rule_id(rule_id: str) -> str:
    """
    Format a rule ID

    Args:
        rule_id: Rule identifier

    Returns:
        Formatted rule ID
    """
    return colorize(rule_id, "bright_blue")


def format_file_path(file_path: str, relative_to: Optional[str] = None) -> str:
    """
    Format a file path, optionally making it relative

    Args:
        file_path: File path to format
        relative_to: Base path to make the path relative to

    Returns:
        Formatted file path
    """
    if relative_to and file_path.startswith(relative_to):
        file_path = os.path.relpath(file_path, relative_to)

    return colorize(file_path, "bright_cyan")


def format_line_number(line_number: Optional[int]) -> str:
    """
    Format a line number

    Args:
        line_number: Line number or None

    Returns:
        Formatted line number string
    """
    if line_number is None:
        return ""

    return colorize(f":{line_number}", "bright_black")


def format_header(text: str, level: int = 1) -> str:
    """
    Format a header with consistent styling

    Args:
        text: Header text
        level: Header level (1=main, 2=section, 3=subsection)

    Returns:
        Formatted header
    """
    width = get_console_width()

    if level == 1:
        # Main header with double line
        styled_text = colorize(text.upper(), "bold")
        return f"\n{styled_text}\n{'=' * min(len(text) + 4, width)}"
    elif level == 2:
        # Section header with single line
        styled_text = colorize(text, "bold")
        return f"\n{styled_text}\n{'-' * min(len(text) + 4, width)}"
    else:
        # Subsection header with no line
        return f"\n{colorize(text, 'bold')}"


def format_success(text: str) -> str:
    """
    Format a success message

    Args:
        text: Success message

    Returns:
        Formatted success message
    """
    return f"✅ {colorize(text, 'green')}"


def format_warning(text: str) -> str:
    """
    Format a warning message

    Args:
        text: Warning message

    Returns:
        Formatted warning message
    """
    return f"⚠️ {colorize(text, 'yellow')}"


def format_error(text: str) -> str:
    """
    Format an error message

    Args:
        text: Error message

    Returns:
        Formatted error message
    """
    return f"❌ {colorize(text, 'red')}"


def format_info(text: str) -> str:
    """
    Format an informational message

    Args:
        text: Info message

    Returns:
        Formatted info message
    """
    return f"ℹ️ {colorize(text, 'blue')}"


def indent(text: str, level: int = 1, indent_size: int = 2) -> str:
    """
    Indent a block of text

    Args:
        text: Text to indent
        level: Indentation level
        indent_size: Number of spaces per indent level

    Returns:
        Indented text
    """
    indent_str = " " * (level * indent_size)
    return "\n".join(f"{indent_str}{line}" for line in text.splitlines())


def format_code_block(code: str, language: str = "") -> str:
    """
    Format a code block with syntax highlighting (for terminal)

    Args:
        code: Code to format
        language: Language identifier (ignored in terminal output)

    Returns:
        Formatted code block
    """
    width = get_console_width()
    separator = "-" * width

    return f"\n{separator}\n{code}\n{separator}"


def format_table(
    headers: List[str], rows: List[List[str]], format_headers: bool = True
) -> str:
    """
    Format a table for terminal output

    Args:
        headers: List of column headers
        rows: List of rows (each row is a list of strings)
        format_headers: Whether to format headers as bold

    Returns:
        Formatted table string
    """
    if not headers or not rows:
        return ""

    # Calculate column widths
    widths = [
        max(len(str(row[i])) for row in [headers] + rows) for i in range(len(headers))
    ]

    # Format headers
    if format_headers:
        header_row = " | ".join(
            colorize(str(header).ljust(widths[i]), "bold")
            for i, header in enumerate(headers)
        )
    else:
        header_row = " | ".join(
            str(header).ljust(widths[i]) for i, header in enumerate(headers)
        )

    # Format separator
    separator = "-+-".join("-" * width for width in widths)

    # Format rows
    formatted_rows = []
    for row in rows:
        formatted_row = " | ".join(
            str(cell).ljust(widths[min(i, len(widths) - 1)])
            for i, cell in enumerate(row)
        )
        formatted_rows.append(formatted_row)

    # Combine everything
    return f"{header_row}\n{separator}\n" + "\n".join(formatted_rows)


def format_progress(current: int, total: int, width: int = 40) -> str:
    """
    Format a progress bar

    Args:
        current: Current progress value
        total: Total progress value
        width: Width of progress bar

    Returns:
        Formatted progress bar
    """
    progress = min(1.0, current / max(1, total))
    filled_width = int(width * progress)

    bar = "█" * filled_width + "░" * (width - filled_width)
    percentage = int(progress * 100)

    return f"[{colorize(bar, 'green')}] {percentage}% ({current}/{total})"


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds to a human-readable string

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted duration string
    """
    if seconds < 0.001:
        return f"{seconds * 1000000:.1f}µs"
    elif seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds / 60)
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds:.1f}s"


def format_count(count: int, singular: str, plural: Optional[str] = None) -> str:
    """
    Format a count with singular/plural form

    Args:
        count: Count value
        singular: Singular form of the word
        plural: Plural form of the word (default: singular + 's')

    Returns:
        Formatted count string
    """
    if plural is None:
        plural = f"{singular}s"

    word = singular if count == 1 else plural
    return f"{count} {word}"


def wrap_text(text: str, width: Optional[int] = None) -> str:
    """
    Wrap text to a specific width

    Args:
        text: Text to wrap
        width: Width to wrap at (default: console width)

    Returns:
        Wrapped text
    """
    if width is None:
        width = get_console_width()

    # Simple word-wrap algorithm
    lines = []
    for paragraph in text.splitlines():
        if not paragraph:
            lines.append("")
            continue

        words = paragraph.split()
        current_line = []
        current_length = 0

        for word in words:
            word_length = len(word)

            if current_length + word_length + len(current_line) <= width:
                current_line.append(word)
                current_length += word_length
            else:
                lines.append(" ".join(current_line))
                current_line = [word]
                current_length = word_length

        if current_line:
            lines.append(" ".join(current_line))

    return "\n".join(lines)


def print_error(message: str, stream: TextIO = sys.stderr) -> None:
    """
    Print an error message to stderr

    Args:
        message: Error message
        stream: Output stream (default: stderr)
    """
    print(format_error(message), file=stream)


def print_warning(message: str, stream: TextIO = sys.stdout) -> None:
    """
    Print a warning message

    Args:
        message: Warning message
        stream: Output stream (default: stdout)
    """
    print(format_warning(message), file=stream)


def print_success(message: str, stream: TextIO = sys.stdout) -> None:
    """
    Print a success message

    Args:
        message: Success message
        stream: Output stream (default: stdout)
    """
    print(format_success(message), file=stream)


def print_info(message: str, stream: TextIO = sys.stdout) -> None:
    """
    Print an informational message

    Args:
        message: Info message
        stream: Output stream (default: stdout)
    """
    print(format_info(message), file=stream)
