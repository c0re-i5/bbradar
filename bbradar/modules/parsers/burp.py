"""
Burp Suite output parser.

Handles Burp Suite XML export format (from "Report selected issues"
or full scan export in the Scanner tab).
"""

import html
import xml.etree.ElementTree as ET
from . import register_parser, make_finding

TOOL_NAME = "burp"

# Burp issue type IDs → our vuln_type + severity
# Based on Burp's issue type database
_ISSUE_MAP = {
    # XSS
    "Cross-site scripting": ("xss", "high"),
    "Reflected cross-site scripting": ("xss", "high"),
    "Stored cross-site scripting": ("xss", "high"),
    "DOM-based cross-site scripting": ("xss", "medium"),
    # Injection
    "SQL injection": ("sqli", "critical"),
    "Blind SQL injection": ("sqli", "critical"),
    "OS command injection": ("command_injection", "critical"),
    "Server-side template injection": ("ssti", "critical"),
    "LDAP injection": ("injection", "high"),
    "XPath injection": ("injection", "high"),
    "XML injection": ("injection", "medium"),
    "Header injection": ("crlf", "medium"),
    "HTTP response header injection": ("crlf", "medium"),
    # SSRF
    "Server-side request forgery": ("ssrf", "high"),
    "Out-of-band resource load": ("ssrf", "high"),
    # File inclusion/traversal
    "File path traversal": ("path_traversal", "high"),
    "File path manipulation": ("path_traversal", "medium"),
    "Remote file inclusion": ("rfi", "critical"),
    "Local file inclusion": ("lfi", "high"),
    # Auth/session
    "Broken access control": ("broken_access_control", "high"),
    "Insufficient authorization": ("broken_access_control", "high"),
    "Session token in URL": ("session_management", "medium"),
    "Duplicate cookies set": ("session_management", "low"),
    "Session fixation": ("session_management", "medium"),
    # CSRF
    "Cross-site request forgery": ("csrf", "medium"),
    # Crypto
    "SSL certificate": ("ssl_tls", "medium"),
    "Unencrypted communications": ("ssl_tls", "medium"),
    "Strict transport security not enforced": ("security_headers", "low"),
    "Content type incorrectly stated": ("misconfiguration", "informational"),
    # Info disclosure
    "Information disclosure": ("info_disclosure", "low"),
    "Email addresses disclosed": ("info_disclosure", "informational"),
    "Private IP addresses disclosed": ("info_disclosure", "low"),
    "Directory listing": ("info_disclosure", "medium"),
    "Backup file": ("info_disclosure", "medium"),
    "Source code disclosure": ("info_disclosure", "high"),
    "Internal server error": ("info_disclosure", "informational"),
    "Stack trace disclosed": ("info_disclosure", "medium"),
    "Verbose error messages": ("info_disclosure", "low"),
    # Config
    "Clickjacking": ("clickjacking", "low"),
    "Open redirection": ("open_redirect", "low"),
    "Cross-origin resource sharing": ("cors", "medium"),
    "CORS misconfiguration": ("cors", "medium"),
    "Missing security headers": ("security_headers", "informational"),
    "X-Frame-Options header": ("security_headers", "low"),
    "Content security policy": ("security_headers", "low"),
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse Burp Suite XML export into findings."""
    findings = []

    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return findings

    # Detect format — <issues> wrapper or <items> wrapper
    issues = root.findall(".//issue")
    if not issues:
        issues = root.findall(".//item")

    for issue in issues:
        finding = _parse_issue(issue)
        if finding:
            findings.append(finding)

    return findings


def _parse_issue(issue) -> dict | None:
    """Parse a single Burp issue/item element."""
    name = _text(issue, "name") or _text(issue, "type")
    if not name:
        return None

    # URL / endpoint
    url = _text(issue, "url") or _text(issue, "path") or ""
    host = _text(issue, "host") or ""
    port = None
    port_text = _text(issue, "port")
    if port_text:
        try:
            port = int(port_text)
        except ValueError:
            pass

    if not host and url:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not port and parsed.port:
            port = parsed.port

    # Severity from Burp
    severity_raw = (_text(issue, "severity") or "").lower()
    severity = {
        "high": "high",
        "medium": "medium",
        "low": "low",
        "information": "informational",
        "informational": "informational",
        "false positive": "informational",
    }.get(severity_raw, "informational")

    # Confidence
    confidence = _text(issue, "confidence") or ""

    # Map issue name to vuln_type
    vuln_type = ""
    for pattern, (vtype, default_sev) in _ISSUE_MAP.items():
        if pattern.lower() in name.lower():
            vuln_type = vtype
            # Use Burp's severity if available, otherwise default
            if not severity_raw or severity_raw in ("information", "informational"):
                severity = default_sev
            break

    # Description/detail
    issue_background = _text(issue, "issueBackground") or ""
    issue_detail = _text(issue, "issueDetail") or ""
    remediation_bg = _text(issue, "remediationBackground") or ""
    remediation_detail = _text(issue, "remediationDetail") or ""

    description = _clean_html(issue_detail or issue_background)
    remediation = _clean_html(remediation_detail or remediation_bg)

    # Request/Response
    request = ""
    response = ""
    evidence_parts = []

    for req_resp in issue.findall(".//requestresponse"):
        req_el = req_resp.find("request")
        resp_el = req_resp.find("response")
        if req_el is not None and req_el.text:
            request = req_el.text[:5000]
        if resp_el is not None and resp_el.text:
            response = resp_el.text[:5000]

    # Also check direct request/response children
    if not request:
        req_el = issue.find("request")
        if req_el is not None and req_el.text:
            request = req_el.text[:5000]
    if not response:
        resp_el = issue.find("response")
        if resp_el is not None and resp_el.text:
            response = resp_el.text[:5000]

    # References
    references = []
    for ref in issue.findall(".//reference"):
        ref_text = ref.text if ref.text else ""
        # Extract URLs from HTML reference text
        import re
        urls = re.findall(r'https?://[^\s<>"]+', ref_text)
        references.extend(urls)

    # Vulnerability classifications
    vuln_classifications = _text(issue, "vulnerabilityClassifications") or ""
    cwe_id = ""
    import re
    cwe_match = re.search(r'CWE-(\d+)', vuln_classifications)
    if cwe_match:
        cwe_id = f"CWE-{cwe_match.group(1)}"

    return make_finding(
        tool=TOOL_NAME,
        title=f"{name} on {url or host}" if (url or host) else name,
        severity=severity,
        vuln_type=vuln_type,
        description=description,
        endpoint=url,
        host=host,
        port=port,
        evidence=f"Confidence: {confidence}" if confidence else "",
        request=request,
        response=response,
        cwe_id=cwe_id,
        references=references,
        tags=["burp", vuln_type] if vuln_type else ["burp"],
        raw_data={"issue_name": name, "confidence": confidence},
    )


def _text(elem, tag: str) -> str:
    """Get text content of a child element."""
    child = elem.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return ""


def _clean_html(text: str) -> str:
    """Strip HTML tags and decode entities from Burp descriptions."""
    if not text:
        return ""
    import re
    clean = re.sub(r'<[^>]+>', ' ', text)
    clean = html.unescape(clean)
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
