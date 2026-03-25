"""
Shared utilities for BBRadar.
"""

import json
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def timestamp_now() -> str:
    """Return current UTC timestamp as ISO string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def slugify(text: str) -> str:
    """Convert text to a filesystem-safe slug."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_-]+", "-", text)
    return text.strip("-")


def run_tool(command, timeout: int = 300) -> tuple[int, str, str]:
    """
    Run an external tool safely and return (returncode, stdout, stderr).

    Accepts either a list of arguments (preferred, avoids shell injection)
    or a string (split via shlex for backward compatibility).
    """
    if isinstance(command, str):
        args = shlex.split(command)
    else:
        args = list(command)
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Command not found: {args[0]}"


def format_table(rows: list[dict], columns: list[str] = None) -> str:
    """Format a list of dicts as a simple text table."""
    if not rows:
        return "  (no results)"
    columns = columns or list(rows[0].keys())

    # Calculate column widths
    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            val = str(row.get(col, ""))
            widths[col] = max(widths[col], len(val))

    # Header
    header = " | ".join(col.upper().ljust(widths[col]) for col in columns)
    separator = "-+-".join("-" * widths[col] for col in columns)
    lines = [header, separator]

    # Rows
    for row in rows:
        line = " | ".join(str(row.get(col, "")).ljust(widths[col]) for col in columns)
        lines.append(line)

    return "\n".join(lines)


# Global flag — set by CLI when --no-color is used or NO_COLOR env is set
_no_color = False


def set_no_color(value: bool = True):
    """Disable ANSI color output."""
    global _no_color
    _no_color = value


def severity_color(severity: str) -> str:
    """Return ANSI color code for severity level."""
    if _no_color or os.environ.get("NO_COLOR") is not None:
        return severity
    colors = {
        "critical": "\033[91m",  # bright red
        "high": "\033[31m",      # red
        "medium": "\033[33m",    # yellow
        "low": "\033[36m",       # cyan
        "informational": "\033[37m",  # white
    }
    reset = "\033[0m"
    color = colors.get(severity.lower(), "")
    return f"{color}{severity}{reset}"


def confirm(prompt: str) -> bool:
    """Ask for y/n confirmation."""
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def safe_json_loads(text: str, default=None):
    """Parse JSON safely, returning default on failure."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return default


def ensure_file_dir(file_path: Path):
    """Ensure the parent directory of a file exists."""
    file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
