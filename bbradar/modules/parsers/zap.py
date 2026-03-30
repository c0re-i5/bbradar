"""
OWASP ZAP output parser.

Handles ZAP JSON reports and XML reports (traditional and modern formats).
"""

import json
import defusedxml.ElementTree as ET
from . import register_parser, make_finding

TOOL_NAME = "zap"

# ZAP risk levels → our severity
_RISK_MAP = {
    "0": "informational", "informational": "informational",
    "1": "low", "low": "low",
    "2": "medium", "medium": "medium",
    "3": "high", "high": "high",
}

# ZAP alert IDs + names → vuln_type
_ALERT_TYPE_MAP = {
    "cross site scripting": "xss",
    "cross-site scripting": "xss",
    "sql injection": "sqli",
    "remote file inclusion": "rfi",
    "local file inclusion": "lfi",
    "path traversal": "path_traversal",
    "directory browsing": "info_disclosure",
    "directory listing": "info_disclosure",
    "server side request forgery": "ssrf",
    "ssrf": "ssrf",
    "command injection": "command_injection",
    "remote code execution": "rce",
    "remote os command injection": "command_injection",
    "cross-site request forgery": "csrf",
    "csrf": "csrf",
    "open redirect": "open_redirect",
    "external redirect": "open_redirect",
    "clickjacking": "clickjacking",
    "x-frame-options": "security_headers",
    "content security policy": "security_headers",
    "strict-transport-security": "security_headers",
    "content-type header missing": "security_headers",
    "x-content-type-options": "security_headers",
    "cookie": "session_management",
    "session": "session_management",
    "information disclosure": "info_disclosure",
    "private ip": "info_disclosure",
    "server leaks": "info_disclosure",
    "source code disclosure": "info_disclosure",
    "application error": "info_disclosure",
    "stack trace": "info_disclosure",
    "ssl": "ssl_tls",
    "tls": "ssl_tls",
    "certificate": "ssl_tls",
    "cors": "cors",
    "authentication": "auth_bypass",
    "insecure authentication": "auth_bypass",
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse ZAP output into findings."""
    data = data.strip()

    # Try JSON first
    findings = _try_json(data)
    if findings is not None:
        return findings

    # Try XML
    findings = _try_xml(data)
    if findings is not None:
        return findings

    return []


def _try_json(data: str) -> list[dict] | None:
    """Parse ZAP JSON report."""
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return None

    if not isinstance(parsed, dict):
        return None

    findings = []

    # Modern JSON report format
    sites = parsed.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        host = site.get("@name", site.get("@host", ""))
        port = site.get("@port")
        if port:
            try:
                port = int(port)
            except ValueError:
                port = None

        alerts = site.get("alerts", site.get("alert", []))
        if isinstance(alerts, dict):
            alerts = [alerts]

        for alert in alerts:
            finding = _parse_alert(alert, host, port)
            if finding:
                findings.append(finding)

    # Also handle flat alert list format
    if not findings:
        alerts = parsed.get("alerts", parsed.get("alert", []))
        if isinstance(alerts, list):
            for alert in alerts:
                finding = _parse_alert(alert, "", None)
                if finding:
                    findings.append(finding)

    return findings if findings else None


def _try_xml(data: str) -> list[dict] | None:
    """Parse ZAP XML report."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None

    findings = []

    for site in root.findall(".//site"):
        host = site.get("name", site.get("host", ""))
        port = site.get("port")
        if port:
            try:
                port = int(port)
            except ValueError:
                port = None

        for alert_el in site.findall(".//alertitem"):
            finding = _parse_xml_alert(alert_el, host, port)
            if finding:
                findings.append(finding)

    # Flat format
    if not findings:
        for alert_el in root.findall(".//alertitem"):
            finding = _parse_xml_alert(alert_el, "", None)
            if finding:
                findings.append(finding)

    return findings if findings else None


def _parse_alert(alert: dict, default_host: str, default_port: int | None) -> dict | None:
    """Parse a JSON alert object."""
    name = alert.get("name", alert.get("alert", ""))
    if not name:
        return None

    risk = str(alert.get("riskcode", alert.get("risk", "0")))
    severity = _RISK_MAP.get(risk.lower(), "informational")

    desc = alert.get("desc", alert.get("description", ""))
    solution = alert.get("solution", "")
    reference = alert.get("reference", "")

    # CWE
    cwe_id = ""
    cwe_raw = alert.get("cweid", "")
    if cwe_raw:
        cwe_id = f"CWE-{cwe_raw}" if not str(cwe_raw).startswith("CWE") else str(cwe_raw)

    # Vuln type
    vuln_type = _classify_alert(name)

    # Instances (each is a separate endpoint hit)
    instances = alert.get("instances", [])
    if isinstance(instances, dict):
        instances = instances.get("instance", [])
    if isinstance(instances, dict):
        instances = [instances]

    if instances:
        # Report each instance
        results = []
        for inst in instances[:20]:  # cap at 20 instances
            uri = inst.get("uri", inst.get("url", ""))
            method = inst.get("method", "")
            param = inst.get("param", "")
            evidence_text = inst.get("evidence", "")

            host = default_host
            if uri:
                from urllib.parse import urlparse
                p = urlparse(uri)
                if p.hostname:
                    host = p.hostname

            title = f"{name}"
            if uri:
                title += f" on {uri[:80]}"

            results.append(make_finding(
                tool=TOOL_NAME,
                title=title,
                severity=severity,
                vuln_type=vuln_type,
                description=_clean(desc),
                endpoint=uri,
                host=host,
                port=default_port,
                evidence=f"Method: {method}\nParameter: {param}\nEvidence: {evidence_text}",
                cwe_id=cwe_id,
                references=_extract_refs(reference),
                tags=["zap"],
                raw_data={"alert_name": name, "confidence": alert.get("confidence", "")},
            ))

        if results:
            return results[0]  # Return first, rest will be deduped
        return None
    else:
        # No instances — single finding
        url = alert.get("url", alert.get("uri", ""))
        return make_finding(
            tool=TOOL_NAME,
            title=f"{name}" + (f" on {url[:80]}" if url else ""),
            severity=severity,
            vuln_type=vuln_type,
            description=_clean(desc),
            endpoint=url,
            host=default_host,
            port=default_port,
            cwe_id=cwe_id,
            references=_extract_refs(reference),
            tags=["zap"],
            raw_data={"alert_name": name},
        )


def _parse_xml_alert(alert_el, default_host: str, default_port: int | None) -> dict | None:
    """Parse an XML alertitem element."""
    name = _xml_text(alert_el, "alert") or _xml_text(alert_el, "name") or ""
    if not name:
        return None

    risk = _xml_text(alert_el, "riskcode") or "0"
    severity = _RISK_MAP.get(risk, "informational")
    desc = _xml_text(alert_el, "desc") or ""
    solution = _xml_text(alert_el, "solution") or ""
    uri = _xml_text(alert_el, "uri") or _xml_text(alert_el, "url") or ""
    method = _xml_text(alert_el, "method") or ""
    param = _xml_text(alert_el, "param") or ""
    evidence_text = _xml_text(alert_el, "evidence") or ""
    reference = _xml_text(alert_el, "reference") or ""

    cwe_raw = _xml_text(alert_el, "cweid") or ""
    cwe_id = f"CWE-{cwe_raw}" if cwe_raw else ""

    vuln_type = _classify_alert(name)

    host = default_host
    if uri:
        from urllib.parse import urlparse
        p = urlparse(uri)
        if p.hostname:
            host = p.hostname

    return make_finding(
        tool=TOOL_NAME,
        title=f"{name}" + (f" on {uri[:80]}" if uri else ""),
        severity=severity,
        vuln_type=vuln_type,
        description=_clean(desc),
        endpoint=uri,
        host=host,
        port=default_port,
        evidence=f"Method: {method}\nParameter: {param}\nEvidence: {evidence_text}",
        cwe_id=cwe_id,
        references=_extract_refs(reference),
        tags=["zap"],
    )


def _classify_alert(name: str) -> str:
    name_lower = name.lower()
    for keyword, vtype in _ALERT_TYPE_MAP.items():
        if keyword in name_lower:
            return vtype
    return "misconfiguration"


def _xml_text(elem, tag: str) -> str:
    child = elem.find(tag)
    return child.text.strip() if child is not None and child.text else ""


def _clean(text: str) -> str:
    """Strip HTML tags from ZAP descriptions."""
    if not text:
        return ""
    import re
    import html
    clean = re.sub(r'<[^>]+>', ' ', text)
    clean = html.unescape(clean)
    return re.sub(r'\s+', ' ', clean).strip()


def _extract_refs(ref_text: str) -> list[str]:
    """Extract URLs from reference text."""
    if not ref_text:
        return []
    import re
    return re.findall(r'https?://[^\s<>"]+', ref_text)


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
