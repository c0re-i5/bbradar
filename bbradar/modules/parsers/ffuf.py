"""
ffuf output parser.

Handles ffuf JSON output (-of json).  Extracts discovered endpoints,
status codes, and content lengths for directory/file brute-forcing.
"""

import json
import logging
from . import register_parser, make_finding

logger = logging.getLogger(__name__)

TOOL_NAME = "ffuf"

# Status codes that indicate interesting findings
_INTERESTING_CODES = {
    200: "informational",
    201: "informational",
    204: "informational",
    301: "informational",
    302: "informational",
    401: "low",        # auth required → potential auth bypass target
    403: "low",        # forbidden → potential bypass target
    405: "informational",
    500: "low",        # server error → potential vuln
    502: "informational",
    503: "informational",
}

# Directory/filename patterns that signal vulns
_SENSITIVE_PATTERNS = {
    "admin": ("info_disclosure", "medium", "Admin panel discovered"),
    "phpmyadmin": ("info_disclosure", "medium", "phpMyAdmin panel discovered"),
    "wp-admin": ("info_disclosure", "low", "WordPress admin panel"),
    "wp-login": ("info_disclosure", "low", "WordPress login page"),
    ".git": ("info_disclosure", "high", "Git repository exposed"),
    ".svn": ("info_disclosure", "high", "SVN repository exposed"),
    ".env": ("info_disclosure", "critical", "Environment file exposed"),
    ".htaccess": ("info_disclosure", "medium", ".htaccess file accessible"),
    ".htpasswd": ("info_disclosure", "high", ".htpasswd file accessible"),
    "backup": ("info_disclosure", "medium", "Backup file/directory discovered"),
    ".bak": ("info_disclosure", "medium", "Backup file discovered"),
    ".sql": ("info_disclosure", "high", "SQL dump file discovered"),
    ".zip": ("info_disclosure", "medium", "Archive file discovered"),
    ".tar": ("info_disclosure", "medium", "Archive file discovered"),
    "config": ("info_disclosure", "medium", "Configuration file/directory"),
    "debug": ("info_disclosure", "medium", "Debug endpoint discovered"),
    "trace": ("misconfiguration", "low", "Trace endpoint discovered"),
    "console": ("info_disclosure", "high", "Debug console exposed"),
    "actuator": ("info_disclosure", "high", "Spring Actuator endpoints exposed"),
    "swagger": ("info_disclosure", "low", "API documentation exposed"),
    "api-docs": ("info_disclosure", "low", "API documentation exposed"),
    "graphql": ("info_disclosure", "low", "GraphQL endpoint discovered"),
    "server-status": ("info_disclosure", "medium", "Apache server-status exposed"),
    "server-info": ("info_disclosure", "medium", "Apache server-info exposed"),
    "phpinfo": ("info_disclosure", "medium", "phpinfo() page exposed"),
    "test": ("info_disclosure", "low", "Test endpoint discovered"),
    "upload": ("file_upload", "medium", "Upload endpoint discovered"),
    "shell": ("info_disclosure", "high", "Potential web shell"),
    "cmd": ("info_disclosure", "high", "Potential command execution endpoint"),
    "cgi-bin": ("info_disclosure", "low", "CGI directory discovered"),
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse ffuf JSON output into findings."""
    findings = []

    try:
        parsed = json.loads(data)
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse %s JSON output: %s", TOOL_NAME, e)
        return findings

    if not isinstance(parsed, dict):
        return findings

    commandline = parsed.get("commandline", "")
    config = parsed.get("config", {})
    results = parsed.get("results", [])

    if not results:
        return findings

    # Extract base URL from config or commandline
    base_url = ""
    if config:
        base_url = config.get("url", "")
    if not base_url and commandline:
        import re
        url_match = re.search(r'-u\s+(\S+)', commandline)
        if url_match:
            base_url = url_match.group(1)

    # Extract host from base URL
    host = ""
    if base_url:
        from urllib.parse import urlparse
        p = urlparse(base_url.replace("FUZZ", ""))
        host = p.hostname or ""

    for result in results:
        input_data = result.get("input", {})
        fuzz_word = input_data.get("FUZZ", "") if isinstance(input_data, dict) else ""
        status = result.get("status", 0)
        length = result.get("length", 0)
        words = result.get("words", 0)
        lines = result.get("lines", 0)
        url = result.get("url", "")
        redirect_location = result.get("redirectlocation", "")

        if not url:
            url = base_url.replace("FUZZ", fuzz_word) if base_url and fuzz_word else ""

        # Classify
        vuln_type, severity, extra_desc = _classify_endpoint(fuzz_word, url, status)

        evidence = f"URL: {url}\nStatus: {status}\nLength: {length}\nWords: {words}\nLines: {lines}"
        if redirect_location:
            evidence += f"\nRedirect: {redirect_location}"

        title = f"Discovered: {url or fuzz_word} [{status}]"

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=title,
            severity=severity,
            vuln_type=vuln_type,
            description=extra_desc or f"Endpoint discovered via content discovery: {url} (HTTP {status})",
            endpoint=url,
            host=host,
            evidence=evidence,
            tags=["ffuf", "content-discovery", f"http-{status}"],
            raw_data={"fuzz_word": fuzz_word, "status": status, "length": length},
        ))

    return findings


def _classify_endpoint(fuzz_word: str, url: str, status: int) -> tuple[str, str, str]:
    """Classify a discovered endpoint by sensitivity."""
    combined = f"{fuzz_word} {url}".lower()

    for pattern, (vtype, sev, desc) in _SENSITIVE_PATTERNS.items():
        if pattern in combined:
            # Only flag if accessible (2xx) or partially accessible (403 for bypass attempts)
            if 200 <= status < 400:
                return vtype, sev, desc
            elif status == 403:
                return vtype, "informational", f"{desc} (403 Forbidden — potential bypass target)"

    # Status-based severity for generic endpoints
    severity = _INTERESTING_CODES.get(status, "informational")
    if status == 500:
        return "info_disclosure", "low", f"Server error at {url} — may indicate vuln"

    return "info_disclosure", severity, ""


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
