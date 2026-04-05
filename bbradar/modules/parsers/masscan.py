"""
Masscan output parser.

Handles Masscan JSON output (-oJ) and grepable/list output.
Extracts open ports and services.
"""

import json
import logging
from . import register_parser, make_finding

logger = logging.getLogger(__name__)

TOOL_NAME = "masscan"


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse masscan output into findings."""
    findings = []

    stripped = data.strip()
    if not stripped:
        return findings

    # Try JSON format first (masscan -oJ)
    if stripped.startswith("[") or stripped.startswith("{"):
        findings = _parse_json(stripped)
        if findings:
            return findings

    # Try list/grepable format (masscan -oL or -oG)
    findings = _parse_list(stripped)
    return findings


def _parse_json(data: str) -> list[dict]:
    """Parse masscan JSON output."""
    findings = []

    # masscan JSON wraps entries in an array with a trailing ",\n" issue
    # Clean up: remove trailing comma before ]
    cleaned = data.rstrip().rstrip(",")
    if not cleaned.endswith("]"):
        cleaned += "]"
    if not cleaned.startswith("["):
        cleaned = "[" + cleaned

    try:
        entries = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning("Failed to parse %s JSON output: %s", TOOL_NAME, e)
        return findings

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("ip", "")
        if not ip:
            continue

        for port_info in entry.get("ports", []):
            port = port_info.get("port")
            proto = port_info.get("proto", "tcp")
            status = port_info.get("status", "")
            service = port_info.get("service", {})
            svc_name = ""
            svc_banner = ""
            if isinstance(service, dict):
                svc_name = service.get("name", "")
                svc_banner = service.get("banner", "")

            if status != "open":
                continue

            endpoint = f"{ip}:{port}"
            svc_desc = svc_name or f"{port}/{proto}"

            findings.append(make_finding(
                tool=TOOL_NAME,
                title=f"Open Port: {port}/{proto} ({svc_desc})" if svc_name else f"Open Port: {port}/{proto}",
                severity="informational",
                vuln_type="info_disclosure",
                description=(
                    f"Open port {port}/{proto} on {ip}.\n"
                    f"Service: {svc_name}\n"
                    f"Banner: {svc_banner}" if svc_banner else
                    f"Open port {port}/{proto} on {ip}.\n"
                    f"Service: {svc_name}" if svc_name else
                    f"Open port {port}/{proto} on {ip}."
                ),
                endpoint=endpoint,
                host=ip,
                port=port,
                evidence=f"{port}/{proto} open {svc_desc}",
                tags=["port-scan", "masscan"],
                raw_data=entry,
            ))

    return findings


def _parse_list(data: str) -> list[dict]:
    """Parse masscan list/grepable output."""
    findings = []

    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # List format: open tcp 80 10.0.0.1 1700000000
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open":
            proto = parts[1]
            try:
                port = int(parts[2])
            except ValueError:
                continue
            ip = parts[3]
            endpoint = f"{ip}:{port}"

            findings.append(make_finding(
                tool=TOOL_NAME,
                title=f"Open Port: {port}/{proto}",
                severity="informational",
                vuln_type="info_disclosure",
                description=f"Open port {port}/{proto} on {ip}.",
                endpoint=endpoint,
                host=ip,
                port=port,
                evidence=f"{port}/{proto} open",
                tags=["port-scan", "masscan"],
            ))

    return findings


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
