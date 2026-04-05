"""
Qualys output parser.

Handles Qualys CSV and XML scan report exports from Qualys WAS and VM.
"""

import csv
import io
import logging
import defusedxml.ElementTree as ET
from . import register_parser, make_finding

logger = logging.getLogger(__name__)

TOOL_NAME = "qualys"

_SEVERITY_MAP = {
    "5": "critical",
    "4": "high",
    "3": "medium",
    "2": "low",
    "1": "informational",
    "urgent": "critical",
    "critical": "critical",
    "serious": "high",
    "high": "high",
    "medium": "medium",
    "minimal": "low",
    "low": "low",
    "informational": "informational",
    "info": "informational",
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse Qualys output into findings."""
    stripped = data.strip()

    if stripped.startswith("<?xml") or stripped.startswith("<"):
        return _parse_xml(data)
    elif "," in stripped.split("\n")[0]:
        return _parse_csv(data)
    return []


def _parse_xml(data: str) -> list[dict]:
    """Parse Qualys XML output."""
    findings = []
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        logger.warning("Failed to parse %s XML output: %s", TOOL_NAME, e)
        return findings

    # WAS format: <WAS_SCAN_REPORT> → <GLOSSARY> → <QID_LIST> → <QID>
    # VM format: <ASSET_DATA_REPORT> or <HOST_LIST> → <HOST> → <VULN_INFO_LIST>

    # Try WAS format
    for vuln in root.findall(".//VULNERABILITY"):
        qid = vuln.findtext("QID", "")
        title = vuln.findtext("TITLE", "") or f"QID-{qid}"
        severity_raw = vuln.findtext("SEVERITY", "")
        severity = _SEVERITY_MAP.get(severity_raw, "medium")
        description = vuln.findtext("DIAGNOSIS", "") or vuln.findtext("DESCRIPTION", "")
        solution = vuln.findtext("SOLUTION", "") or vuln.findtext("CONSEQUENCE", "")
        url = vuln.findtext("URL", "") or ""

        cve_id = ""
        for cve_el in vuln.findall(".//CVE"):
            cid = cve_el.findtext("ID", "") or (cve_el.text or "")
            if cid.startswith("CVE-") and not cve_id:
                cve_id = cid

        cvss = None
        cvss_text = vuln.findtext("CVSS_BASE", "") or vuln.findtext("CVSS", "")
        if cvss_text:
            try:
                cvss = float(cvss_text)
            except ValueError:
                pass

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=title,
            severity=severity,
            vuln_type="other",
            description=description[:3000],
            endpoint=url,
            host=_extract_host(url) if url else "",
            evidence=solution[:2000],
            cve_id=cve_id,
            cvss_score=cvss,
            tags=[f"QID:{qid}"] if qid else [],
        ))

    # Try VM host format
    for host_el in root.findall(".//HOST"):
        host_ip = host_el.findtext("IP", "") or host_el.findtext("ip", "")
        for det in host_el.findall(".//DETECTION"):
            qid = det.findtext("QID", "")
            title = det.findtext("TITLE", "") or f"QID-{qid}"
            severity_raw = det.findtext("SEVERITY", "")
            severity = _SEVERITY_MAP.get(severity_raw, "medium")
            results = det.findtext("RESULTS", "")

            port = None
            port_text = det.findtext("PORT", "")
            if port_text:
                try:
                    port = int(port_text)
                except ValueError:
                    pass

            findings.append(make_finding(
                tool=TOOL_NAME,
                title=title,
                severity=severity,
                vuln_type="other",
                description=results[:3000],
                host=host_ip,
                port=port,
                endpoint=f"{host_ip}:{port}" if port else host_ip,
                tags=[f"QID:{qid}"] if qid else [],
            ))

    return findings


def _parse_csv(data: str) -> list[dict]:
    """Parse Qualys CSV export."""
    findings = []

    # Skip header lines that start with non-CSV content
    lines = data.strip().split("\n")
    csv_start = 0
    for i, line in enumerate(lines):
        if "," in line and not line.startswith("#"):
            csv_start = i
            break

    csv_data = "\n".join(lines[csv_start:])
    reader = csv.DictReader(io.StringIO(csv_data))

    for row in reader:
        title = row.get("Title", row.get("title", row.get("QID Title", "")))
        if not title:
            continue
        severity_raw = row.get("Severity", row.get("severity", "")).strip().lower()
        severity = _SEVERITY_MAP.get(severity_raw, "medium")
        host = row.get("IP", row.get("ip", row.get("DNS", "")))
        port = None
        port_val = row.get("Port", row.get("port", ""))
        if port_val:
            try:
                port = int(port_val)
            except ValueError:
                pass

        cve_id = row.get("CVE ID", row.get("cve_id", ""))
        cvss = None
        cvss_text = row.get("CVSS Base", row.get("CVSS", ""))
        if cvss_text:
            try:
                cvss = float(cvss_text)
            except ValueError:
                pass

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=title,
            severity=severity,
            vuln_type="other",
            description=row.get("Diagnosis", row.get("Results", ""))[:3000],
            host=host,
            port=port,
            endpoint=f"{host}:{port}" if port else host,
            cve_id=cve_id,
            cvss_score=cvss,
            tags=[f"QID:{row.get('QID', '')}"] if row.get("QID") else [],
        ))

    return findings


def _extract_host(url: str) -> str:
    """Extract hostname from URL."""
    if "://" in url:
        return url.split("://", 1)[1].split("/")[0].split(":")[0]
    return url.split("/")[0].split(":")[0]


register_parser(TOOL_NAME, __import__(__name__, fromlist=[TOOL_NAME]))
