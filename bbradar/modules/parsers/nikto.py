"""
Nikto output parser.

Handles Nikto JSON output (-Format json) and CSV output (-Format csv).
Falls back to plain text log parsing for standard output.
"""

import csv
import io
import json
from . import register_parser, make_finding

TOOL_NAME = "nikto"

# OSVDB / Nikto ID categories → vuln_type
_ID_MAP = {
    "3092": ("info_disclosure", "low"),      # directory indexing
    "3268": ("info_disclosure", "low"),      # directory listing
    "877": ("misconfiguration", "low"),       # HTTP TRACE
    "999": ("info_disclosure", "informational"),  # robots.txt
    "3233": ("misconfiguration", "low"),     # default page
    "6544": ("info_disclosure", "low"),      # ETag header
    "5737": ("info_disclosure", "informational"),  # X-Powered-By
    "4": ("security_headers", "informational"),  # generic header
}

# Keyword-based vuln_type detection
_KEYWORD_MAP = {
    "directory index": ("info_disclosure", "low"),
    "directory listing": ("info_disclosure", "low"),
    "server leaks": ("info_disclosure", "low"),
    "x-frame-options": ("security_headers", "low"),
    "x-content-type": ("security_headers", "low"),
    "x-xss-protection": ("security_headers", "low"),
    "content-security-policy": ("security_headers", "low"),
    "strict-transport": ("security_headers", "medium"),
    "cookie": ("session_management", "low"),
    "httponly": ("session_management", "low"),
    "default file": ("info_disclosure", "low"),
    "backup": ("info_disclosure", "medium"),
    "source code": ("info_disclosure", "high"),
    "php": ("info_disclosure", "low"),
    "sql": ("sqli", "high"),
    "injection": ("injection", "high"),
    "xss": ("xss", "medium"),
    "cross-site": ("xss", "medium"),
    "remote file": ("rfi", "high"),
    "local file": ("lfi", "high"),
    "traversal": ("path_traversal", "high"),
    "rce": ("rce", "critical"),
    "command": ("command_injection", "high"),
    "shellshock": ("rce", "critical"),
    "upload": ("file_upload", "medium"),
    "admin": ("info_disclosure", "low"),
    "phpmyadmin": ("info_disclosure", "medium"),
    "login": ("info_disclosure", "informational"),
    "outdated": ("misconfiguration", "medium"),
    "obsolete": ("misconfiguration", "medium"),
    "vulnerable": ("known_cve", "high"),
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse nikto output into findings."""
    data = data.strip()

    # Try JSON
    findings = _try_json(data)
    if findings:
        return findings

    # Try CSV
    findings = _try_csv(data)
    if findings:
        return findings

    # Fall back to text
    return _parse_text(data)


def _try_json(data: str) -> list[dict] | None:
    """Try to parse as Nikto JSON output."""
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return None

    findings = []

    if isinstance(parsed, dict):
        # Single host
        _parse_json_host(parsed, findings)
    elif isinstance(parsed, list):
        for item in parsed:
            if isinstance(item, dict):
                _parse_json_host(item, findings)

    return findings if findings else None


def _parse_json_host(obj: dict, findings: list):
    """Parse a single Nikto JSON host entry."""
    host = obj.get("host", obj.get("ip", ""))
    port = obj.get("port")
    if port:
        try:
            port = int(port)
        except (ValueError, TypeError):
            port = None

    vulnerabilities = obj.get("vulnerabilities", [])
    if not vulnerabilities and "items" in obj:
        vulnerabilities = obj["items"]

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue

        method = vuln.get("method", "GET")
        url = vuln.get("url", vuln.get("uri", ""))
        msg = vuln.get("msg", vuln.get("message", ""))
        osvdb = str(vuln.get("OSVDB", vuln.get("osvdb", vuln.get("id", ""))))

        endpoint = f"{host}:{port}{url}" if port else f"{host}{url}"

        vuln_type, severity = _classify(msg, osvdb)

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=f"Nikto: {msg[:80]}" if msg else f"Nikto finding at {url}",
            severity=severity,
            vuln_type=vuln_type,
            description=msg,
            endpoint=endpoint,
            host=host,
            port=port,
            evidence=f"OSVDB-{osvdb}: {method} {url}\n{msg}" if osvdb else f"{method} {url}\n{msg}",
            tags=["nikto", f"OSVDB-{osvdb}"] if osvdb and osvdb != "0" else ["nikto"],
            raw_data=vuln,
        ))


def _try_csv(data: str) -> list[dict] | None:
    """Try to parse as Nikto CSV output."""
    # Nikto CSV format: "host","IP","port","uri","method","OSVDB","msg"
    lines = data.strip().split("\n")
    if len(lines) < 2:
        return None

    # Check for CSV header
    first = lines[0]
    if not ("," in first and ('"' in first or "host" in first.lower())):
        return None

    findings = []
    try:
        reader = csv.reader(io.StringIO(data))
        for row in reader:
            if len(row) < 7:
                continue
            host_val, ip, port_val, uri, method, osvdb, msg = row[:7]
            if host_val.lower() == "host":
                continue  # header

            port = None
            try:
                port = int(port_val)
            except ValueError:
                pass

            host = host_val or ip
            endpoint = f"{host}:{port}{uri}" if port else f"{host}{uri}"
            vuln_type, severity = _classify(msg, osvdb)

            findings.append(make_finding(
                tool=TOOL_NAME,
                title=f"Nikto: {msg[:80]}",
                severity=severity,
                vuln_type=vuln_type,
                description=msg,
                endpoint=endpoint,
                host=host,
                port=port,
                evidence=f"OSVDB-{osvdb}: {method} {uri}\n{msg}",
                tags=["nikto", f"OSVDB-{osvdb}"] if osvdb and osvdb != "0" else ["nikto"],
            ))
    except csv.Error:
        return None

    return findings if findings else None


def _parse_text(data: str) -> list[dict]:
    """Parse plain-text Nikto output."""
    findings = []

    host = ""
    port = None

    for line in data.split("\n"):
        line = line.strip()

        # Extract target
        if line.startswith("+ Target IP:") or line.startswith("+ Target Host:"):
            host = line.split(":", 1)[-1].strip()
        elif line.startswith("+ Target Port:"):
            try:
                port = int(line.split(":", 1)[-1].strip())
            except ValueError:
                pass
        elif line.startswith("+ OSVDB-") or (line.startswith("+ ") and ":" in line and "Server:" not in line and "Target" not in line):
            msg = line.lstrip("+ ").strip()

            osvdb = ""
            if msg.startswith("OSVDB-"):
                parts = msg.split(":", 1)
                osvdb = parts[0].replace("OSVDB-", "").strip()
                if len(parts) > 1:
                    msg = parts[1].strip()

            vuln_type, severity = _classify(msg, osvdb)

            findings.append(make_finding(
                tool=TOOL_NAME,
                title=f"Nikto: {msg[:80]}",
                severity=severity,
                vuln_type=vuln_type,
                description=msg,
                host=host,
                port=port,
                evidence=line,
                tags=["nikto"],
            ))

    return findings


def _classify(msg: str, osvdb: str = "") -> tuple[str, str]:
    """Classify a Nikto finding by message content."""
    msg_lower = (msg or "").lower()

    # Check OSVDB map
    if osvdb and osvdb in _ID_MAP:
        return _ID_MAP[osvdb]

    # Keyword match
    for keyword, (vtype, sev) in _KEYWORD_MAP.items():
        if keyword in msg_lower:
            return vtype, sev

    return "misconfiguration", "informational"


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
