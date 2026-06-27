"""
test_formatter.py - Tests for console output formatting utilities
"""

import io

import pytest

from ghast.utils import formatter
from ghast.utils.formatter import (
    COLORS,
    SEVERITY_COLORS,
    SEVERITY_SYMBOLS,
    colorize,
    format_code_block,
    format_count,
    format_duration,
    format_error,
    format_file_path,
    format_header,
    format_info,
    format_line_number,
    format_progress,
    format_rule_id,
    format_severity,
    format_success,
    format_table,
    format_warning,
    get_console_width,
    indent,
    print_error,
    print_info,
    print_success,
    print_warning,
    supports_color,
    wrap_text,
)


@pytest.fixture
def force_color(monkeypatch):
    """Force colorize() to emit ANSI codes regardless of environment."""
    monkeypatch.setattr(formatter, "supports_color", lambda: True)


@pytest.fixture
def no_color(monkeypatch):
    """Force colorize() to skip ANSI codes."""
    monkeypatch.setattr(formatter, "supports_color", lambda: False)


def test_supports_color_disabled_by_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert supports_color() is False


def test_supports_color_disabled_by_ghast_no_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("GHAST_NO_COLOR", "1")
    assert supports_color() is False


def test_supports_color_windows_with_ansicon(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("GHAST_NO_COLOR", raising=False)
    monkeypatch.setattr(formatter.platform, "system", lambda: "Windows")
    monkeypatch.setenv("ANSICON", "1")
    monkeypatch.delenv("WT_SESSION", raising=False)
    monkeypatch.delenv("ConEmuANSI", raising=False)
    monkeypatch.delenv("TERM_PROGRAM", raising=False)
    assert supports_color() is True


def test_supports_color_windows_without_support(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("GHAST_NO_COLOR", raising=False)
    monkeypatch.setattr(formatter.platform, "system", lambda: "Windows")
    for var in ("ANSICON", "WT_SESSION", "ConEmuANSI", "TERM_PROGRAM"):
        monkeypatch.delenv(var, raising=False)
    assert supports_color() is False


def test_supports_color_unix_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("GHAST_NO_COLOR", raising=False)
    monkeypatch.setattr(formatter.platform, "system", lambda: "Linux")

    class _TTY(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(formatter.sys, "stdout", _TTY())
    assert supports_color() is True


def test_supports_color_unix_not_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("GHAST_NO_COLOR", raising=False)
    monkeypatch.setattr(formatter.platform, "system", lambda: "Linux")

    class _NotTTY(io.StringIO):
        def isatty(self):
            return False

    monkeypatch.setattr(formatter.sys, "stdout", _NotTTY())
    assert supports_color() is False


def test_colorize_with_color(force_color):
    result = colorize("hello", "red")
    assert result == f"{COLORS['red']}hello{COLORS['reset']}"


def test_colorize_unknown_color_returns_plain(force_color):
    assert colorize("hello", "not-a-color") == "hello"


def test_colorize_without_color_support(no_color):
    assert colorize("hello", "red") == "hello"


def test_get_console_width_default(monkeypatch):
    monkeypatch.setattr(formatter.shutil, "get_terminal_size", lambda: (123, 40))
    assert get_console_width() == 123


def test_get_console_width_fallback(monkeypatch):
    def _boom():
        raise OSError("no terminal")

    monkeypatch.setattr(formatter.shutil, "get_terminal_size", _boom)
    assert get_console_width() == 80


def test_format_severity_known(no_color):
    result = format_severity("CRITICAL")
    assert SEVERITY_SYMBOLS["CRITICAL"] in result
    assert "CRITICAL" in result


def test_format_severity_unknown(no_color):
    result = format_severity("UNKNOWN")
    assert result.startswith("•")
    assert "UNKNOWN" in result


def test_format_rule_id(force_color):
    result = format_rule_id("check_timeout")
    assert "check_timeout" in result
    assert COLORS["bright_blue"] in result


def test_format_file_path_relative(no_color):
    result = format_file_path("/repo/sub/file.yml", relative_to="/repo")
    assert result == "sub/file.yml"


def test_format_file_path_no_relative(no_color):
    result = format_file_path("/repo/sub/file.yml")
    assert result == "/repo/sub/file.yml"


def test_format_line_number_none():
    assert format_line_number(None) == ""


def test_format_line_number_value(no_color):
    assert format_line_number(42) == ":42"


def test_format_header_levels(no_color, monkeypatch):
    monkeypatch.setattr(formatter, "get_console_width", lambda: 80)
    h1 = format_header("Title", level=1)
    assert "TITLE" in h1
    assert "=" in h1

    h2 = format_header("Section", level=2)
    assert "Section" in h2
    assert "-" in h2

    h3 = format_header("Sub", level=3)
    assert "Sub" in h3


def test_format_message_helpers(no_color):
    assert "Done" in format_success("Done")
    assert "Careful" in format_warning("Careful")
    assert "Boom" in format_error("Boom")
    assert "Note" in format_info("Note")


def test_indent():
    text = "line1\nline2"
    result = indent(text, level=2, indent_size=2)
    assert result == "    line1\n    line2"


def test_format_code_block(monkeypatch):
    monkeypatch.setattr(formatter, "get_console_width", lambda: 10)
    result = format_code_block("print(1)", language="python")
    assert "print(1)" in result
    assert "-" * 10 in result


def test_format_table(no_color):
    headers = ["Name", "Count"]
    rows = [["foo", "1"], ["barbaz", "22"]]
    table = format_table(headers, rows)
    assert "Name" in table
    assert "barbaz" in table
    assert "-+-" in table


def test_format_table_without_header_styling(no_color):
    table = format_table(["A"], [["x"]], format_headers=False)
    assert table.startswith("A")


def test_format_table_empty():
    assert format_table([], []) == ""
    assert format_table(["A"], []) == ""


def test_format_progress(no_color):
    result = format_progress(5, 10, width=10)
    assert "50%" in result
    assert "(5/10)" in result


def test_format_progress_overflow(no_color):
    # current > total should clamp at 100%
    result = format_progress(15, 10, width=10)
    assert "100%" in result


def test_format_progress_zero_total(no_color):
    # total of 0 must not raise ZeroDivisionError (max(1, total) guard)
    result = format_progress(0, 0, width=10)
    assert "0%" in result


@pytest.mark.parametrize(
    "seconds,expected_substr",
    [
        (0.0000005, "µs"),
        (0.05, "ms"),
        (5.0, "s"),
        (125.0, "m "),
    ],
)
def test_format_duration(seconds, expected_substr):
    assert expected_substr in format_duration(seconds)


def test_format_count_singular():
    assert format_count(1, "file") == "1 file"


def test_format_count_plural_default():
    assert format_count(3, "file") == "3 files"


def test_format_count_plural_explicit():
    assert format_count(2, "child", "children") == "2 children"


def test_wrap_text_explicit_width():
    text = "the quick brown fox jumps"
    wrapped = wrap_text(text, width=10)
    for line in wrapped.splitlines():
        assert len(line) <= 10


def test_wrap_text_preserves_blank_lines():
    text = "para one\n\npara two"
    wrapped = wrap_text(text, width=80)
    assert "" in wrapped.splitlines()


def test_wrap_text_default_width(monkeypatch):
    monkeypatch.setattr(formatter, "get_console_width", lambda: 80)
    wrapped = wrap_text("short text")
    assert wrapped == "short text"


def test_print_helpers(no_color):
    out = io.StringIO()
    err = io.StringIO()
    print_error("err", stream=err)
    print_warning("warn", stream=out)
    print_success("ok", stream=out)
    print_info("info", stream=out)

    assert "err" in err.getvalue()
    out_value = out.getvalue()
    assert "warn" in out_value
    assert "ok" in out_value
    assert "info" in out_value


def test_severity_maps_complete():
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        assert severity in SEVERITY_COLORS
        assert severity in SEVERITY_SYMBOLS
