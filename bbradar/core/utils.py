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


# ═══════════════════════════════════════════════════════════════════
# Input Validation
# ═══════════════════════════════════════════════════════════════════

def validate_domain(value: str) -> str | None:
    """Validate a domain name. Returns error message or None if valid."""
    if not value or len(value) > 253:
        return "Domain name is empty or too long (max 253 chars)"
    # Allow wildcards like *.example.com
    clean = value.lstrip("*.")
    if not clean:
        return "Domain name is empty after stripping wildcards"
    labels = clean.split(".")
    for label in labels:
        if not label:
            return "Domain has empty label (double dots)"
        if len(label) > 63:
            return f"Label '{label}' exceeds 63 chars"
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', label):
            return f"Invalid label '{label}' — must be alphanumeric (hyphens allowed in middle)"
    return None


def validate_ip(value: str) -> str | None:
    """Validate an IP address (v4 or v6). Returns error message or None if valid."""
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        return f"'{value}' is not a valid IP address"


def validate_cidr(value: str) -> str | None:
    """Validate a CIDR range. Returns error message or None if valid."""
    import ipaddress
    try:
        ipaddress.ip_network(value, strict=False)
        return None
    except ValueError:
        return f"'{value}' is not a valid CIDR range"


def validate_url(value: str) -> str | None:
    """Validate a URL. Returns error message or None if valid."""
    from urllib.parse import urlparse
    if not value:
        return "URL is empty"
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https", ""):
        return f"Invalid scheme '{parsed.scheme}' — expected http or https"
    if not parsed.netloc and not parsed.path:
        return "URL has no host or path"
    return None


def validate_target_value(value: str, asset_type: str) -> str | None:
    """
    Validate a target value based on its asset type.
    Returns error message string, or None if valid.
    """
    value = value.strip()
    if not value:
        return "Target value is empty"

    validators = {
        "domain": validate_domain,
        "wildcard": validate_domain,
        "ip": validate_ip,
        "cidr": validate_cidr,
        "url": validate_url,
        "api": validate_url,
    }
    validator = validators.get(asset_type)
    if validator:
        return validator(value)
    return None


def validate_cvss_vector(vector: str) -> str | None:
    """
    Validate a CVSS v3.x vector string format.
    Returns error message or None if valid.
    Example valid: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
    """
    if not vector:
        return None
    pattern = r'^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$'
    if not re.match(pattern, vector):
        return (f"Invalid CVSS v3 vector format. Expected: "
                f"CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_")
    return None


def normalize_cwe(cwe_input: str) -> str:
    """
    Normalize CWE references to consistent format: CWE-<number>.
    Accepts: 'CWE-79', 'cwe-79', 'CWE79', '79'
    Returns: 'CWE-79'
    """
    if not cwe_input:
        return cwe_input
    cwe_input = cwe_input.strip().upper()
    # Strip 'CWE-' or 'CWE' prefix to get the number
    cleaned = re.sub(r'^CWE-?', '', cwe_input)
    try:
        num = int(cleaned)
        return f"CWE-{num}"
    except ValueError:
        return cwe_input  # Return as-is if can't parse
