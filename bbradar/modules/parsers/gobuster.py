"""
Gobuster output parser.

Handles gobuster JSON output (-o with --no-progress or text output).
Extracts discovered directories, files, and endpoints.
"""

import json
from . import register_parser, make_finding

TOOL_NAME = "gobuster"

# Status codes that indicate interesting findings
_INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

# Status codes that suggest higher severity
_SENSITIVE_CODES = {
    401: ("medium", "Authentication required — possible sensitive endpoint"),
    403: ("low", "Forbidden — endpoint exists but access denied"),
    500: ("medium", "Internal server error — possible misconfiguration"),
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse gobuster output into findings."""
    findings = []

    stripped = data.strip()
    if not stripped:
        return findings

    # Try JSON format first (gobuster -o file + JSON mode)
    if stripped.startswith("{") or stripped.startswith("["):
        findings = _parse_json(stripped)
        if findings:
            return findings

    # Default: text output
    findings = _parse_text(stripped)
    return findings


def _parse_json(data: str) -> list[dict]:
    """Parse gobuster JSON output."""
    findings = []

    # Handle JSONL (one per line)
    entries = []
    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, list):
                entries.extend(obj)
            elif isinstance(obj, dict):
                entries.append(obj)
        except (json.JSONDecodeError, ValueError):
            continue

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        url = entry.get("url", "") or entry.get("path", "")
        status = entry.get("status", 0)
        length = entry.get("length", entry.get("size", 0))

        if not url:
            continue

        try:
            status = int(status)
        except (ValueError, TypeError):
            status = 0

        if status and status not in _INTERESTING_CODES:
            continue

        severity = "informational"
        description = f"Discovered endpoint: {url} (Status: {status}, Size: {length})"

        if status in _SENSITIVE_CODES:
            severity, extra = _SENSITIVE_CODES[status]
            description += f"\n{extra}"

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=f"Directory/File: {url} [{status}]",
            severity=severity,
            vuln_type="info_disclosure",
            description=description,
            endpoint=url,
            evidence=f"Status: {status}, Size: {length}",
            tags=["directory-brute", "gobuster"],
            raw_data=entry,
        ))

    return findings


def _parse_text(data: str) -> list[dict]:
    """Parse gobuster text output."""
    findings = []

    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("Gobuster"):
            continue
        if "Starting gobuster" in line or "Finished" in line:
            continue
        if "Progress:" in line or "Error:" in line:
            continue

        # Standard format: /path (Status: 200) [Size: 1234]
        url = ""
        status = 0
        length = 0

        if "(Status:" in line:
            parts = line.split("(Status:")
            url = parts[0].strip()
            rest = parts[1] if len(parts) > 1 else ""
            try:
                status = int(rest.split(")")[0].strip())
            except (ValueError, IndexError):
                pass
            if "[Size:" in rest:
                try:
                    length = int(rest.split("[Size:")[1].split("]")[0].strip())
                except (ValueError, IndexError):
                    pass
        elif line.startswith("/") or line.startswith("http"):
            # Simple path listing
            parts = line.split()
            url = parts[0]
            if len(parts) > 1:
                try:
                    status = int(parts[1].strip("()[]"))
                except ValueError:
                    pass

        if not url:
            continue

        if status and status not in _INTERESTING_CODES:
            continue

        severity = "informational"
        description = f"Discovered endpoint: {url} (Status: {status}, Size: {length})"

        if status in _SENSITIVE_CODES:
            severity, extra = _SENSITIVE_CODES[status]
            description += f"\n{extra}"

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=f"Directory/File: {url} [{status}]",
            severity=severity,
            vuln_type="info_disclosure",
            description=description,
            endpoint=url,
            evidence=f"Status: {status}, Size: {length}",
            tags=["directory-brute", "gobuster"],
        ))

    return findings


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
