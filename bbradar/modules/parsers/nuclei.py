"""
Nuclei output parser.

Handles both JSONL (one JSON object per line, default -jsonl output)
and JSON array format.

Nuclei findings come pre-structured with severity, CWE, CVSS, CVE,
template IDs, and matched evidence — making them the richest source.
"""

import json
from . import register_parser, make_finding

TOOL_NAME = "nuclei"

# Map nuclei severity strings
_SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "unknown": "informational",
}

# Map nuclei template tags to our vuln_type
_TAG_TYPE_MAP = {
    "xss": "xss",
    "sqli": "sqli",
    "ssrf": "ssrf",
    "rce": "rce",
    "lfi": "lfi",
    "rfi": "rfi",
    "redirect": "open_redirect",
    "open-redirect": "open_redirect",
    "ssti": "ssti",
    "xxe": "xxe",
    "idor": "idor",
    "csrf": "csrf",
    "crlf": "crlf",
    "injection": "injection",
    "command-injection": "command_injection",
    "deserialization": "deserialization",
    "upload": "file_upload",
    "traversal": "path_traversal",
    "auth-bypass": "auth_bypass",
    "default-login": "default_credentials",
    "exposure": "info_disclosure",
    "disclosure": "info_disclosure",
    "misconfig": "misconfiguration",
    "misconfiguration": "misconfiguration",
    "takeover": "subdomain_takeover",
    "subdomain-takeover": "subdomain_takeover",
    "cors": "cors",
    "header": "security_headers",
    "cve": "known_cve",
    "token": "info_disclosure",
    "unauth": "broken_access_control",
    "waf": "misconfiguration",
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse nuclei JSON/JSONL output into findings."""
    findings = []
    objects = _load_objects(data)

    for obj in objects:
        finding = _parse_one(obj)
        if finding:
            findings.append(finding)

    return findings


def _load_objects(data: str) -> list[dict]:
    """Load JSON objects from JSONL or JSON array."""
    objects = []

    # Try JSONL first (most common nuclei output)
    for line in data.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                objects.append(obj)
            elif isinstance(obj, list):
                objects.extend(o for o in obj if isinstance(o, dict))
        except json.JSONDecodeError:
            continue

    if not objects:
        # Try full JSON array
        try:
            parsed = json.loads(data)
            if isinstance(parsed, list):
                objects = [o for o in parsed if isinstance(o, dict)]
            elif isinstance(parsed, dict):
                objects = [parsed]
        except json.JSONDecodeError:
            pass

    return objects


def _parse_one(obj: dict) -> dict | None:
    """Parse a single nuclei result object."""
    template_id = obj.get("template-id", obj.get("templateID", ""))
    if not template_id:
        return None

    info = obj.get("info", {}) or {}
    classification = info.get("classification", {}) or {}

    matched_at = obj.get("matched-at", obj.get("host", ""))
    host = obj.get("host", obj.get("ip", ""))
    matcher_name = obj.get("matcher-name", "")

    # Title
    name = info.get("name", template_id)
    title = name
    if matcher_name:
        title = f"{name} [{matcher_name}]"

    # Severity
    severity = _SEV_MAP.get(
        (info.get("severity", "unknown") or "unknown").lower(),
        "informational"
    )

    # Extract tags and map to vuln_type
    tags_raw = info.get("tags", "")
    if isinstance(tags_raw, list):
        tags = tags_raw
    elif isinstance(tags_raw, str):
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
    else:
        tags = []

    vuln_type = ""
    for tag in tags:
        tag_lower = tag.lower()
        if tag_lower in _TAG_TYPE_MAP:
            vuln_type = _TAG_TYPE_MAP[tag_lower]
            break

    # CVE / CWE / CVSS
    cve_id = ""
    cve_list = classification.get("cve-id", [])
    if isinstance(cve_list, list) and cve_list:
        cve_id = cve_list[0]
    elif isinstance(cve_list, str):
        cve_id = cve_list

    cwe_id = ""
    cwe_list = classification.get("cwe-id", [])
    if isinstance(cwe_list, list) and cwe_list:
        cwe_id = str(cwe_list[0])
    elif isinstance(cwe_list, str):
        cwe_id = cwe_list

    cvss_score = classification.get("cvss-score")
    if cvss_score is not None:
        try:
            cvss_score = float(cvss_score)
        except (ValueError, TypeError):
            cvss_score = None

    # Description
    description = info.get("description", "")

    # References
    refs = info.get("reference", [])
    if isinstance(refs, str):
        refs = [refs] if refs else []
    elif not isinstance(refs, list):
        refs = []

    # Evidence
    evidence_parts = []
    extracted = obj.get("extracted-results", [])
    if extracted:
        evidence_parts.append("Extracted: " + ", ".join(str(e) for e in extracted[:10]))
    matched_words = obj.get("matched-words", [])
    if matched_words:
        evidence_parts.append("Matched: " + ", ".join(str(w) for w in matched_words[:10]))
    curl_cmd = obj.get("curl-command", "")
    if curl_cmd:
        evidence_parts.append(f"Curl: {curl_cmd}")

    # Request / Response
    request = obj.get("request", "")
    response = obj.get("response", "")

    # Port
    port = None
    if obj.get("port"):
        try:
            port = int(obj["port"])
        except (ValueError, TypeError):
            pass

    return make_finding(
        tool=TOOL_NAME,
        title=title,
        severity=severity,
        vuln_type=vuln_type or ("known_cve" if cve_id else ""),
        description=description,
        endpoint=matched_at,
        host=host,
        port=port,
        evidence="\n".join(evidence_parts),
        request=request[:5000] if request else "",
        response=response[:5000] if response else "",
        cve_id=cve_id,
        cwe_id=cwe_id,
        cvss_score=cvss_score,
        references=refs,
        tags=tags,
        raw_data={"template_id": template_id, "matcher_name": matcher_name},
    )


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
