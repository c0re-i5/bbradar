"""
Fortify (Micro Focus / OpenText) output parser.

Handles Fortify FPR XML extract and FVDL (Fortify Vulnerability Description Language) format.
"""

import defusedxml.ElementTree as ET
from . import register_parser, make_finding

TOOL_NAME = "fortify"

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "4.0": "critical",
    "3.0": "high",
    "2.0": "medium",
    "1.0": "low",
    "0.0": "informational",
}

_TYPE_MAP = {
    "sql injection": "sqli",
    "cross-site scripting": "xss",
    "command injection": "command_injection",
    "path manipulation": "path_traversal",
    "path traversal": "path_traversal",
    "open redirect": "open_redirect",
    "csrf": "csrf",
    "cross-site request forgery": "csrf",
    "xml external entity": "xxe",
    "xxe": "xxe",
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "deserialization": "deserialization",
    "insecure deserialization": "deserialization",
    "information disclosure": "info_disclosure",
    "privacy violation": "info_disclosure",
    "password management": "auth_bypass",
    "weak cryptograph": "info_disclosure",
    "race condition": "race_condition",
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse Fortify output into findings."""
    findings = []

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return findings

    # Strip namespace for easier element finding
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    # FVDL format: <FVDL> → <Vulnerabilities> → <Vulnerability>
    for vuln in root.findall(f".//{ns}Vulnerability"):
        class_info = vuln.find(f"{ns}ClassInfo")
        instance_info = vuln.find(f"{ns}InstanceInfo")
        analysis_info = vuln.find(f"{ns}AnalysisInfo")

        category = ""
        subcategory = ""
        if class_info is not None:
            category = class_info.findtext(f"{ns}Type", "")
            subcategory = class_info.findtext(f"{ns}Subtype", "")

        title = f"{category}: {subcategory}" if subcategory else category or "Fortify Finding"

        # Severity from InstanceInfo or ClassInfo
        severity_raw = ""
        if instance_info is not None:
            severity_raw = instance_info.findtext(f"{ns}InstanceSeverity", "")
        if not severity_raw and class_info is not None:
            severity_raw = class_info.findtext(f"{ns}DefaultSeverity", "")
        severity = _SEVERITY_MAP.get(severity_raw.lower().strip(), "medium")

        # Source file and line
        source_file = ""
        line_num = ""
        primary = vuln.find(f".//{ns}Primary")
        if primary is not None:
            entry = primary.find(f"{ns}Entry")
            if entry is not None:
                node = entry.find(f"{ns}Node")
                if node is not None:
                    source_loc = node.find(f"{ns}SourceLocation")
                    if source_loc is not None:
                        source_file = source_loc.get("path", "")
                        line_num = source_loc.get("line", "")

        # CWE from ClassInfo
        cwe_id = ""
        kingdom = ""
        if class_info is not None:
            kingdom = class_info.findtext(f"{ns}Kingdom", "")

        # Map vuln type
        vuln_type = "other"
        title_lower = title.lower()
        for key, vtype in _TYPE_MAP.items():
            if key in title_lower:
                vuln_type = vtype
                break

        description = f"Category: {category}"
        if subcategory:
            description += f"\nSubcategory: {subcategory}"
        if kingdom:
            description += f"\nKingdom: {kingdom}"
        if source_file:
            description += f"\nFile: {source_file}"
            if line_num:
                description += f" (line {line_num})"

        endpoint = source_file
        if line_num:
            endpoint = f"{source_file}:{line_num}"

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=title,
            severity=severity,
            vuln_type=vuln_type,
            description=description,
            endpoint=endpoint,
            evidence=f"File: {source_file}, Line: {line_num}" if source_file else "",
            cwe_id=cwe_id,
        ))

    # Also handle simpler <Issue> or <Result> format from some exports
    for issue in root.findall(".//Issue") + root.findall(".//Result"):
        name = issue.findtext("Category", "") or issue.findtext("Name", "")
        severity_raw = issue.findtext("Friority", "") or issue.findtext("Severity", "")
        severity = _SEVERITY_MAP.get(severity_raw.lower().strip(), "medium")
        filepath = issue.findtext("Primary/Entry/Node/SourceLocation/@path", "") or issue.findtext("File", "")

        if name:
            vuln_type = "other"
            for key, vtype in _TYPE_MAP.items():
                if key in name.lower():
                    vuln_type = vtype
                    break

            findings.append(make_finding(
                tool=TOOL_NAME,
                title=name,
                severity=severity,
                vuln_type=vuln_type,
                description=issue.findtext("Abstract", "") or "",
                endpoint=filepath,
            ))

    return findings


register_parser(TOOL_NAME, __import__(__name__, fromlist=[TOOL_NAME]))
