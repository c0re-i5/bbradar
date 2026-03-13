"""
testssl.sh output parser.

Handles testssl.sh JSON output (--jsonfile / --json-pretty).
Parses TLS/SSL certificate and protocol findings.
"""

import json
from . import register_parser, make_finding

TOOL_NAME = "testssl"

# testssl severity mapping
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "low",
    "INFO": "informational",
    "OK": "informational",
}

# Known finding IDs → enhanced classification
_ID_MAP = {
    "heartbleed": ("ssl_tls", "critical", "CVE-2014-0160"),
    "CCS": ("ssl_tls", "high", "CVE-2014-0224"),
    "ticketbleed": ("ssl_tls", "high", "CVE-2016-9244"),
    "ROBOT": ("ssl_tls", "high", ""),
    "secure_renego": ("ssl_tls", "medium", "CVE-2009-3555"),
    "secure_client_renego": ("ssl_tls", "medium", ""),
    "CRIME_TLS": ("ssl_tls", "high", "CVE-2012-4929"),
    "BREACH": ("ssl_tls", "medium", "CVE-2013-3587"),
    "POODLE_SSL": ("ssl_tls", "high", "CVE-2014-3566"),
    "fallback_SCSV": ("ssl_tls", "low", ""),
    "SWEET32": ("ssl_tls", "medium", "CVE-2016-2183"),
    "FREAK": ("ssl_tls", "high", "CVE-2015-0204"),
    "DROWN": ("ssl_tls", "high", "CVE-2016-0800"),
    "LOGJAM": ("ssl_tls", "high", "CVE-2015-4000"),
    "BEAST": ("ssl_tls", "medium", "CVE-2011-3389"),
    "LUCKY13": ("ssl_tls", "medium", "CVE-2013-0169"),
    "RC4": ("ssl_tls", "medium", "CVE-2013-2566"),
    "SSLv2": ("ssl_tls", "critical", ""),
    "SSLv3": ("ssl_tls", "high", ""),
    "TLS1": ("ssl_tls", "low", ""),
    "TLS1_1": ("ssl_tls", "low", ""),
    "cert_expirationStatus": ("ssl_tls", "high", ""),
    "cert_chain_of_trust": ("ssl_tls", "high", ""),
    "cert_CN": ("ssl_tls", "medium", ""),
    "cert_SAN": ("ssl_tls", "medium", ""),
    "cert_signatureAlgorithm": ("ssl_tls", "medium", ""),
    "cert_keySize": ("ssl_tls", "medium", ""),
    "HSTS": ("security_headers", "medium", ""),
    "HPKP": ("security_headers", "informational", ""),
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse testssl.sh JSON output."""
    findings = []

    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return findings

    if isinstance(parsed, dict):
        # Pretty JSON format wraps in object
        items = parsed.get("scanResult", parsed.get("findings", []))
        if isinstance(items, list) and items:
            # scanResult is a list of host blocks
            for host_block in items:
                if isinstance(host_block, dict):
                    ip = host_block.get("ip", host_block.get("targetHost", ""))
                    port = host_block.get("port")
                    host_findings = host_block.get("finding", host_block.get("findings", []))
                    if isinstance(host_findings, list):
                        for item in host_findings:
                            f = _parse_item(item, ip, port)
                            if f:
                                findings.append(f)
                elif isinstance(host_block, list):
                    for item in host_block:
                        f = _parse_item(item, "", None)
                        if f:
                            findings.append(f)
        else:
            # Flat findings in the object
            for key, val in parsed.items():
                if isinstance(val, dict) and "finding" in val:
                    f = _parse_item(val, "", None)
                    if f:
                        findings.append(f)

    elif isinstance(parsed, list):
        # Flat JSON array format
        for item in parsed:
            f = _parse_item(item, "", None)
            if f:
                findings.append(f)

    return findings


def _parse_item(item: dict, default_ip: str, default_port) -> dict | None:
    """Parse a single testssl finding item."""
    if not isinstance(item, dict):
        return None

    finding_id = item.get("id", "")
    sev_raw = item.get("severity", item.get("finding_severity", "INFO"))
    finding_text = item.get("finding", "")
    ip = item.get("ip", default_ip)
    port = item.get("port", default_port)
    cve_str = item.get("cve", "")

    if port:
        try:
            port = int(port)
        except (ValueError, TypeError):
            port = None

    # Skip purely OK/informational results unless they're about something notable
    severity = _SEVERITY_MAP.get(sev_raw, "informational")
    if severity == "informational" and finding_id not in _ID_MAP:
        return None

    # Classify
    vuln_type = "ssl_tls"
    cve_id = cve_str
    if finding_id in _ID_MAP:
        vuln_type, mapped_sev, mapped_cve = _ID_MAP[finding_id]
        if sev_raw in ("OK", "INFO"):
            # testssl says it's OK → finding is just informational (not vuln)
            if "not vulnerable" in finding_text.lower() or "offered" not in finding_text.lower():
                return None
        else:
            severity = mapped_sev
        if mapped_cve and not cve_id:
            cve_id = mapped_cve

    endpoint = f"{ip}:{port}" if port else ip

    return make_finding(
        tool=TOOL_NAME,
        title=f"testssl: {finding_id} — {finding_text[:80]}",
        severity=severity,
        vuln_type=vuln_type,
        description=finding_text,
        endpoint=endpoint,
        host=ip,
        port=port,
        cve_id=cve_id,
        evidence=f"[{finding_id}] {sev_raw}: {finding_text}",
        tags=["testssl", "tls", finding_id] if finding_id else ["testssl", "tls"],
        raw_data=item,
    )


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
