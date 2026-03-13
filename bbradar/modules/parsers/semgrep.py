"""
Semgrep output parser.

Handles Semgrep JSON output (--json) and SARIF output (--sarif).
Parses static analysis findings with rule metadata.
"""

import json
from . import register_parser, make_finding

TOOL_NAME = "semgrep"

# Semgrep severity → our severity
_SEV_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "INVENTORY": "informational",
    "EXPERIMENT": "informational",
}

# SARIF level → our severity
_SARIF_SEV = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "informational",
}

# Rule ID patterns → vuln_type
_RULE_PATTERNS = {
    "sql": "sqli",
    "xss": "xss",
    "injection": "injection",
    "command-injection": "command_injection",
    "ssrf": "ssrf",
    "deserialization": "deserialization",
    "xxe": "xxe",
    "path-traversal": "path_traversal",
    "open-redirect": "open_redirect",
    "csrf": "csrf",
    "crypto": "cryptographic_issue",
    "hardcoded-secret": "info_disclosure",
    "hardcoded-password": "info_disclosure",
    "jwt": "auth_bypass",
    "cors": "cors",
    "insecure-transport": "ssl_tls",
    "missing-auth": "auth_bypass",
    "ldap": "injection",
    "xpath": "injection",
    "ssti": "injection",
    "template-injection": "injection",
    "log-injection": "injection",
    "header-injection": "injection",
    "eval": "rce",
    "exec": "rce",
    "dangerous-function": "rce",
    "insecure-hash": "cryptographic_issue",
    "weak-random": "cryptographic_issue",
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse Semgrep JSON or SARIF output."""
    data = data.strip()

    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return []

    if not isinstance(parsed, dict):
        return []

    # Detect SARIF vs native JSON
    if "$schema" in parsed or parsed.get("version") == "2.1.0":
        return _parse_sarif(parsed)

    return _parse_json(parsed)


def _parse_json(parsed: dict) -> list[dict]:
    """Parse native Semgrep JSON output."""
    findings = []
    results = parsed.get("results", [])

    for result in results:
        if not isinstance(result, dict):
            continue

        check_id = result.get("check_id", "")
        path = result.get("path", "")
        start = result.get("start", {})
        end = result.get("end", {})
        extra = result.get("extra", {})

        message = extra.get("message", "")
        severity = _SEV_MAP.get(extra.get("severity", ""), "medium")
        metadata = extra.get("metadata", {})
        lines = extra.get("lines", "")
        fix = extra.get("fix", "")

        # Location
        start_line = start.get("line", 0)
        end_line = end.get("line", start_line)
        endpoint = f"{path}:{start_line}" if path else ""

        # CWE
        cwe_id = ""
        cwe_list = metadata.get("cwe", [])
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list]
        if cwe_list:
            cwe_id = str(cwe_list[0])
            if not cwe_id.startswith("CWE"):
                cwe_id = f"CWE-{cwe_id}"

        # References
        refs = metadata.get("references", [])
        if isinstance(refs, str):
            refs = [refs]

        # Classify
        vuln_type = _classify_rule(check_id, metadata)

        # OWASP
        owasp = metadata.get("owasp", [])

        evidence = f"Rule: {check_id}\nFile: {path}:{start_line}-{end_line}\n"
        if lines:
            evidence += f"Code:\n{lines}\n"
        if fix:
            evidence += f"Suggested fix:\n{fix}"

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=f"Semgrep: {check_id}",
            severity=severity,
            vuln_type=vuln_type,
            description=message,
            endpoint=endpoint,
            evidence=evidence,
            cwe_id=cwe_id,
            references=refs,
            tags=["semgrep", check_id.split(".")[-1]] + (owasp if isinstance(owasp, list) else []),
            raw_data=result,
        ))

    return findings


def _parse_sarif(parsed: dict) -> list[dict]:
    """Parse SARIF output from Semgrep."""
    findings = []

    runs = parsed.get("runs", [])
    for run in runs:
        tool_info = run.get("tool", {}).get("driver", {})
        rules_list = tool_info.get("rules", [])
        rules = {r.get("id", ""): r for r in rules_list}

        results = run.get("results", [])
        for result in results:
            rule_id = result.get("ruleId", "")
            level = result.get("level", "warning")
            severity = _SARIF_SEV.get(level, "medium")

            message = result.get("message", {}).get("text", "")

            # Location
            locations = result.get("locations", [])
            path = ""
            start_line = 0
            region_text = ""
            if locations:
                phys = locations[0].get("physicalLocation", {})
                path = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                start_line = region.get("startLine", 0)
                region_text = region.get("snippet", {}).get("text", "")

            endpoint = f"{path}:{start_line}" if path else ""

            # Rule metadata
            rule_meta = rules.get(rule_id, {})
            properties = rule_meta.get("properties", {})

            cwe_id = ""
            cwe_tags = [t for t in properties.get("tags", []) if t.startswith("CWE")]
            if cwe_tags:
                cwe_id = cwe_tags[0]

            refs = [r.get("url", "") for r in rule_meta.get("helpUri", [])] if isinstance(rule_meta.get("helpUri"), list) else []
            help_uri = rule_meta.get("helpUri", "")
            if isinstance(help_uri, str) and help_uri:
                refs.append(help_uri)

            vuln_type = _classify_rule(rule_id, properties)

            evidence = f"Rule: {rule_id}\nFile: {path}:{start_line}\n"
            if region_text:
                evidence += f"Code:\n{region_text}"

            findings.append(make_finding(
                tool=TOOL_NAME,
                title=f"Semgrep: {rule_id}",
                severity=severity,
                vuln_type=vuln_type,
                description=message,
                endpoint=endpoint,
                evidence=evidence,
                cwe_id=cwe_id,
                references=[r for r in refs if r],
                tags=["semgrep", "sarif"],
                raw_data=result,
            ))

    return findings


def _classify_rule(rule_id: str, metadata: dict) -> str:
    """Classify a Semgrep rule to vuln_type."""
    # Check metadata category first
    category = metadata.get("category", "")
    if category:
        cat_lower = category.lower()
        for pattern, vtype in _RULE_PATTERNS.items():
            if pattern in cat_lower:
                return vtype

    # Check rule ID
    rule_lower = rule_id.lower()
    for pattern, vtype in _RULE_PATTERNS.items():
        if pattern in rule_lower:
            return vtype

    return "code_quality"


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
