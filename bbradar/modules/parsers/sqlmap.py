"""
sqlmap output parser.

Handles sqlmap log files (target.txt / log) and session CSV data.
Extracts confirmed SQL injection findings from sqlmap output.
"""

import json
import os
import re
from . import register_parser, make_finding

TOOL_NAME = "sqlmap"

# Injection type mapping
_INJECTION_TYPES = {
    "boolean-based blind": ("sqli", "high", "Boolean-based blind SQL injection"),
    "time-based blind": ("sqli", "high", "Time-based blind SQL injection"),
    "error-based": ("sqli", "high", "Error-based SQL injection"),
    "union query": ("sqli", "high", "UNION query SQL injection"),
    "stacked queries": ("sqli", "critical", "Stacked queries SQL injection"),
    "inline query": ("sqli", "high", "Inline query SQL injection"),
}

# DBMS → CWE mapping
_CWE = "CWE-89"


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse sqlmap output."""
    data = data.strip()

    # Try JSON (sqlmap API output)
    findings = _try_json(data)
    if findings is not None:
        return findings

    # Parse text log
    return _parse_log(data, filename)


def _try_json(data: str) -> list[dict] | None:
    """Try to parse as sqlmap JSON API output."""
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return None

    if not isinstance(parsed, dict):
        return None

    findings = []

    # sqlmap API stores results per URL
    data_section = parsed.get("data", {})
    if not isinstance(data_section, dict):
        return findings if findings else None

    for key, value in data_section.items():
        if isinstance(value, dict) and "value" in value:
            items = value["value"]
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        f = _parse_json_finding(item, parsed)
                        if f:
                            findings.append(f)

    return findings if findings else None


def _parse_json_finding(item: dict, context: dict) -> dict | None:
    """Parse a JSON-format sqlmap finding."""
    place = item.get("place", "")
    parameter = item.get("parameter", "")
    dbms = item.get("dbms", "")
    title = item.get("title", "")
    payload = item.get("payload", item.get("vector", ""))

    url = context.get("url", "")
    host = ""
    if url:
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.hostname or ""

    inj_type = title.lower() if title else ""
    vuln_type, severity, desc = "sqli", "high", "SQL injection confirmed"
    for pattern, (vt, sev, d) in _INJECTION_TYPES.items():
        if pattern in inj_type:
            vuln_type, severity, desc = vt, sev, d
            break

    evidence = f"Parameter: {parameter}\nPlace: {place}\nDBMS: {dbms}\n"
    if title:
        evidence += f"Type: {title}\n"
    if payload:
        evidence += f"Payload: {payload}"

    return make_finding(
        tool=TOOL_NAME,
        title=f"SQLi: {parameter} ({title or 'confirmed'})",
        severity=severity,
        vuln_type=vuln_type,
        description=f"{desc} in parameter '{parameter}'" + (f" ({dbms})" if dbms else ""),
        endpoint=url,
        host=host,
        cwe_id=_CWE,
        evidence=evidence,
        tags=["sqlmap", "sqli", place.lower()] if place else ["sqlmap", "sqli"],
        raw_data=item,
    )


def _parse_log(data: str, filename: str) -> list[dict]:
    """Parse sqlmap text log output."""
    findings = []
    current_url = ""
    current_host = ""
    current_params = []

    for line in data.split("\n"):
        line = line.strip()

        # Target URL
        url_match = re.search(r'(?:URL|target url|testing url)[:\s]+(\S+)', line, re.IGNORECASE)
        if url_match:
            current_url = url_match.group(1)
            from urllib.parse import urlparse
            p = urlparse(current_url)
            current_host = p.hostname or ""

        # Vulnerable parameter confirmation
        if "is vulnerable" in line.lower() or "parameter" in line.lower() and "injectable" in line.lower():
            param_match = re.search(r"(?:parameter|GET|POST|COOKIE)\s+'?([^'\"]+)'?\s+(?:is vulnerable|appears to be.*injectable)", line, re.IGNORECASE)
            if param_match:
                param = param_match.group(1).strip()
                if param not in current_params:
                    current_params.append(param)
                    findings.append(make_finding(
                        tool=TOOL_NAME,
                        title=f"SQLi confirmed: {param}",
                        severity="high",
                        vuln_type="sqli",
                        description=f"SQL injection confirmed in parameter '{param}'",
                        endpoint=current_url,
                        host=current_host,
                        cwe_id=_CWE,
                        evidence=line,
                        tags=["sqlmap", "sqli"],
                    ))

        # Injection type details
        for pattern, (vt, sev, desc) in _INJECTION_TYPES.items():
            if pattern in line.lower() and ("payload" in line.lower() or "injectable" in line.lower()):
                payload_match = re.search(r'[Pp]ayload:\s*(.+)', line)
                payload = payload_match.group(1) if payload_match else ""

                findings.append(make_finding(
                    tool=TOOL_NAME,
                    title=f"SQLi ({desc})",
                    severity=sev,
                    vuln_type=vt,
                    description=desc,
                    endpoint=current_url,
                    host=current_host,
                    cwe_id=_CWE,
                    evidence=f"{line}" + (f"\nPayload: {payload}" if payload else ""),
                    tags=["sqlmap", "sqli", pattern.replace(" ", "-")],
                ))
                break

        # Database/table/column extraction confirmations
        if re.search(r'available databases|current database|fetched data logged|dumped to', line, re.IGNORECASE):
            findings.append(make_finding(
                tool=TOOL_NAME,
                title=f"SQLi data extraction confirmed",
                severity="critical",
                vuln_type="sqli",
                description=f"sqlmap successfully extracted data: {line}",
                endpoint=current_url,
                host=current_host,
                cwe_id=_CWE,
                evidence=line,
                tags=["sqlmap", "sqli", "data-extraction"],
            ))

    return findings


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
