"""
Veracode output parser.

Handles Veracode XML detailed report format (detailedreport.do export).
"""

import xml.etree.ElementTree as ET
from . import register_parser, make_finding

TOOL_NAME = "veracode"

_SEVERITY_MAP = {
    "5": "critical",
    "4": "high",
    "3": "medium",
    "2": "low",
    "1": "informational",
    "0": "informational",
    "very high": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "very low": "informational",
    "informational": "informational",
}

_TYPE_MAP = {
    "crlf injection": "crlf",
    "command injection": "command_injection",
    "os command injection": "command_injection",
    "sql injection": "sqli",
    "cross-site scripting": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "directory traversal": "path_traversal",
    "path traversal": "path_traversal",
    "server-side request forgery": "ssrf",
    "ssrf": "ssrf",
    "xml external entity": "xxe",
    "xxe": "xxe",
    "csrf": "csrf",
    "cross-site request forgery": "csrf",
    "open redirect": "open_redirect",
    "url redirector abuse": "open_redirect",
    "authentication bypass": "auth_bypass",
    "improper authentication": "auth_bypass",
    "insecure deserialization": "deserialization",
    "information leakage": "info_disclosure",
    "information exposure": "info_disclosure",
    "broken access control": "broken_access_control",
    "insufficient authorization": "broken_access_control",
    "ssti": "ssti",
    "template injection": "ssti",
    "race condition": "race_condition",
    "cors": "cors",
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse Veracode XML report into findings."""
    findings = []

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return findings

    # Strip namespace
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    # detailedreport format: <detailedreport> → <severity> → <category> → <cwe> → <staticflaws>/<dynamicflaws> → <flaw>
    for flaw in root.findall(f".//{ns}flaw"):
        severity_raw = flaw.get("severity", "")
        severity = _SEVERITY_MAP.get(severity_raw, "medium")
        category_name = flaw.get("categoryname", "")
        cwe_id_raw = flaw.get("cweid", "")
        cwe_id = f"CWE-{cwe_id_raw}" if cwe_id_raw else ""
        module = flaw.get("module", "")
        source_file = flaw.get("sourcefile", "")
        line = flaw.get("line", "")
        url = flaw.get("url", "")
        description = flaw.get("description", "")
        remediation = flaw.get("remediation_status", "")

        # Map vuln type
        vuln_type = "other"
        cat_lower = category_name.lower()
        for key, vtype in _TYPE_MAP.items():
            if key in cat_lower:
                vuln_type = vtype
                break

        endpoint = url or source_file
        if source_file and line:
            endpoint = f"{source_file}:{line}"

        desc_parts = []
        if description:
            desc_parts.append(description[:2000])
        if module:
            desc_parts.append(f"Module: {module}")
        if source_file:
            loc = f"File: {source_file}"
            if line:
                loc += f" (line {line})"
            desc_parts.append(loc)

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=category_name or "Veracode Finding",
            severity=severity,
            vuln_type=vuln_type,
            description="\n".join(desc_parts),
            endpoint=endpoint,
            host="",
            cwe_id=cwe_id,
        ))

    # Also handle SCA (software composition analysis) findings
    for component in root.findall(f".//{ns}component"):
        for vuln_el in component.findall(f"{ns}vulnerabilities/{ns}vulnerability"):
            cve_id = vuln_el.get("cve_id", "") or vuln_el.findtext(f"{ns}cve_id", "")
            cvss = None
            cvss_text = vuln_el.get("cvss_score", "") or vuln_el.findtext(f"{ns}cvss_score", "")
            if cvss_text:
                try:
                    cvss = float(cvss_text)
                except ValueError:
                    pass

            severity_raw = vuln_el.get("severity", "")
            severity = _SEVERITY_MAP.get(str(severity_raw).lower(), "medium")

            lib_name = component.get("library", "") or component.get("filename", "")
            title = f"Vulnerable Component: {lib_name}" if lib_name else "Vulnerable Component"
            if cve_id:
                title += f" ({cve_id})"

            findings.append(make_finding(
                tool=TOOL_NAME,
                title=title,
                severity=severity,
                vuln_type="other",
                description=vuln_el.get("description", "") or vuln_el.findtext(f"{ns}description", "") or "",
                cve_id=cve_id,
                cvss_score=cvss,
                endpoint=lib_name,
            ))

    return findings


register_parser(TOOL_NAME, __import__(__name__, fromlist=[TOOL_NAME]))
