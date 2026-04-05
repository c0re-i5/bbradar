"""
Acunetix output parser.

Handles Acunetix XML export format used by the web vulnerability scanner.
"""

import logging
import defusedxml.ElementTree as ET
from . import register_parser, make_finding

logger = logging.getLogger(__name__)

TOOL_NAME = "acunetix"

_SEVERITY_MAP = {
    "3": "critical",
    "2": "high",
    "1": "medium",
    "0": "low",
    "informational": "informational",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

_TYPE_MAP = {
    "xss": "xss",
    "cross site scripting": "xss",
    "sql injection": "sqli",
    "blind sql injection": "sqli",
    "command injection": "command_injection",
    "os command injection": "command_injection",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "file inclusion": "lfi",
    "remote file inclusion": "rfi",
    "local file inclusion": "lfi",
    "ssrf": "ssrf",
    "server side request forgery": "ssrf",
    "csrf": "csrf",
    "cross site request forgery": "csrf",
    "open redirect": "open_redirect",
    "xxe": "xxe",
    "xml external entity": "xxe",
    "information disclosure": "info_disclosure",
    "sensitive data": "info_disclosure",
    "broken authentication": "auth_bypass",
    "authentication bypass": "auth_bypass",
    "insecure deserialization": "deserialization",
    "ssti": "ssti",
    "template injection": "ssti",
    "cors": "cors",
    "crlf injection": "crlf",
    "header injection": "hhi",
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse Acunetix XML output into findings."""
    findings = []

    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        logger.warning("Failed to parse %s XML output: %s", TOOL_NAME, e)
        return findings

    # Acunetix XML has <Scan> → <ReportItems> → <ReportItem> structure
    # Also handles <ScanGroup> → <Scan> → <ReportItems>
    for item in root.findall(".//ReportItem"):
        name = item.findtext("Name", "") or item.findtext("name", "")
        severity_raw = (item.findtext("Severity", "") or
                        item.findtext("severity", "") or
                        item.findtext("Type", "") or "").strip().lower()
        severity = _SEVERITY_MAP.get(severity_raw, "medium")

        url = item.findtext("Affects", "") or item.findtext("URL", "") or ""
        description = item.findtext("Description", "") or ""
        impact = item.findtext("Impact", "") or ""
        remediation = item.findtext("Recommendation", "") or item.findtext("Remedy", "") or ""

        cwe_text = item.findtext("CWE", "") or ""
        cwe_id = ""
        if cwe_text:
            cwe_id = f"CWE-{cwe_text}" if not cwe_text.startswith("CWE-") else cwe_text

        cvss = None
        cvss_text = item.findtext("CVSS", "") or item.findtext("CVSSScore", "")
        if cvss_text:
            try:
                cvss = float(cvss_text.split()[0])
            except (ValueError, IndexError):
                pass

        request = item.findtext("TechnicalDetails", "") or item.findtext("Request", "") or ""
        response = item.findtext("Response", "") or ""

        # Map vuln type
        vuln_type = "other"
        name_lower = name.lower()
        for key, vtype in _TYPE_MAP.items():
            if key in name_lower:
                vuln_type = vtype
                break

        refs = []
        for ref in item.findall(".//Reference"):
            ref_url = ref.findtext("URL", "") or ref.text or ""
            if ref_url:
                refs.append(ref_url)

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=name or "Acunetix Finding",
            severity=severity,
            vuln_type=vuln_type,
            description=description,
            endpoint=url,
            host=_extract_host(url),
            evidence=impact,
            request=request[:4000],
            response=response[:4000],
            cwe_id=cwe_id,
            cvss_score=cvss,
            references=refs,
        ))

    return findings


def _extract_host(url: str) -> str:
    """Extract hostname from URL."""
    if "://" in url:
        host = url.split("://", 1)[1].split("/")[0].split(":")[0]
        return host
    return url.split("/")[0].split(":")[0]


register_parser(TOOL_NAME, __import__(__name__, fromlist=[TOOL_NAME]))
