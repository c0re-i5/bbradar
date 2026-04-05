"""
Metasploit output parser.

Handles Metasploit XML export (db_export) and JSON output formats.
"""

import defusedxml.ElementTree as ET
import json
import logging
from . import register_parser, make_finding

logger = logging.getLogger(__name__)

TOOL_NAME = "metasploit"

_SEVERITY_MAP = {
    "exploit": "critical",
    "dos": "high",
    "auxiliary": "medium",
    "post": "medium",
    "info": "informational",
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse Metasploit output into findings."""
    findings = []

    # Try XML first (db_export format)
    if data.strip().startswith("<?xml") or data.strip().startswith("<MetasploitV"):
        findings = _parse_xml(data)
    else:
        # Try JSON
        try:
            parsed = json.loads(data)
            findings = _parse_json(parsed)
        except (json.JSONDecodeError, ValueError):
            # Try log format
            findings = _parse_log(data)

    return findings


def _parse_xml(data: str) -> list[dict]:
    """Parse Metasploit XML db_export."""
    findings = []
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        logger.warning("Failed to parse %s XML output: %s", TOOL_NAME, e)
        return findings

    # Parse vulns from db_export
    for vuln_el in root.findall(".//vuln"):
        name = vuln_el.findtext("name", "")
        host_el = vuln_el.find(".//host")
        host = ""
        if host_el is not None:
            host = host_el.findtext("address", "") or host_el.get("address", "")
        port = None
        port_el = vuln_el.find(".//port")
        if port_el is not None:
            try:
                port = int(port_el.text or port_el.get("number", "0"))
            except (ValueError, TypeError):
                pass

        refs = []
        cve_id = ""
        for ref in vuln_el.findall(".//ref"):
            ref_text = ref.text or ""
            refs.append(ref_text)
            if ref_text.startswith("CVE-") and not cve_id:
                cve_id = ref_text

        severity = "medium"
        info = (vuln_el.findtext("info", "") or "").lower()
        for key, sev in _SEVERITY_MAP.items():
            if key in info:
                severity = sev
                break

        endpoint = f"{host}:{port}" if port else host
        findings.append(make_finding(
            tool=TOOL_NAME,
            title=name or "Metasploit Finding",
            severity=severity,
            vuln_type="other",
            description=vuln_el.findtext("info", "") or "",
            host=host,
            port=port,
            endpoint=endpoint,
            cve_id=cve_id,
            references=refs,
        ))

    # Parse hosts for service info
    for host_el in root.findall(".//host"):
        host_addr = host_el.findtext("address", "") or host_el.get("address", "")
        for svc in host_el.findall(".//service"):
            port_str = svc.findtext("port", "") or svc.get("port", "")
            svc_name = svc.findtext("name", "") or svc.get("name", "")
            svc_info = svc.findtext("info", "") or svc.get("info", "")
            try:
                port = int(port_str)
            except (ValueError, TypeError):
                port = None

            if svc_name:
                findings.append(make_finding(
                    tool=TOOL_NAME,
                    title=f"Service Detected: {svc_name} on {host_addr}:{port}",
                    severity="informational",
                    description=f"Service: {svc_name}\nInfo: {svc_info}",
                    host=host_addr,
                    port=port,
                    endpoint=f"{host_addr}:{port}",
                ))

    return findings


def _parse_json(data) -> list[dict]:
    """Parse Metasploit JSON output."""
    findings = []
    items = data if isinstance(data, list) else [data]

    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name", item.get("module_name", ""))
        host = item.get("host", item.get("rhosts", ""))
        port = item.get("port", item.get("rport"))
        cve_id = ""
        refs = item.get("references", [])
        if isinstance(refs, list):
            for r in refs:
                if str(r).startswith("CVE-") and not cve_id:
                    cve_id = str(r)

        if isinstance(port, str):
            try:
                port = int(port)
            except ValueError:
                port = None

        mod_type = item.get("type", item.get("mod_type", "")).lower()
        severity = _SEVERITY_MAP.get(mod_type, "medium")

        endpoint = f"{host}:{port}" if port else str(host)
        findings.append(make_finding(
            tool=TOOL_NAME,
            title=name or "Metasploit Finding",
            severity=severity,
            vuln_type="other",
            description=item.get("description", item.get("info", "")),
            host=str(host),
            port=port,
            endpoint=endpoint,
            cve_id=cve_id,
            references=[str(r) for r in refs] if isinstance(refs, list) else [],
        ))

    return findings


def _parse_log(data: str) -> list[dict]:
    """Parse Metasploit console log output."""
    findings = []
    current_host = ""

    for line in data.splitlines():
        line = line.strip()
        # Look for [+] and [*] lines with exploit results
        if line.startswith("[+]"):
            msg = line[3:].strip()
            findings.append(make_finding(
                tool=TOOL_NAME,
                title=msg[:200],
                severity="high",
                vuln_type="other",
                description=msg,
                host=current_host,
                endpoint=current_host,
            ))
        elif "RHOSTS =>" in line or "RHOST =>" in line:
            parts = line.split("=>")
            if len(parts) > 1:
                current_host = parts[1].strip()

    return findings


register_parser(TOOL_NAME, __import__(__name__, fromlist=[TOOL_NAME]))
