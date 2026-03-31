"""
WhatWeb output parser.

Handles WhatWeb JSON output (--log-json or -oJ).
Extracts technology fingerprints and version information.
"""

import json
from . import register_parser, make_finding

TOOL_NAME = "whatweb"

# Technologies that indicate potential security concerns
_SECURITY_CONCERNS = {
    "php": ("low", "PHP detected — check version for known CVEs"),
    "wordpress": ("low", "WordPress detected — check for known plugin/theme vulnerabilities"),
    "joomla": ("low", "Joomla detected — check for known vulnerabilities"),
    "drupal": ("low", "Drupal detected — check for known vulnerabilities"),
    "apache": ("informational", "Apache web server detected"),
    "nginx": ("informational", "Nginx web server detected"),
    "iis": ("informational", "IIS web server detected"),
    "tomcat": ("low", "Apache Tomcat detected — check for manager panel exposure"),
    "jenkins": ("medium", "Jenkins detected — check for unauthenticated access"),
    "weblogic": ("medium", "Oracle WebLogic detected — check for known RCE vulnerabilities"),
    "coldfusion": ("medium", "Adobe ColdFusion detected — check for known vulnerabilities"),
    "elasticsearch": ("medium", "Elasticsearch detected — check for unauthenticated access"),
    "phpmyadmin": ("medium", "phpMyAdmin detected — check for default credentials"),
    "wp-login": ("low", "WordPress login page exposed"),
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse WhatWeb output into findings."""
    findings = []

    stripped = data.strip()
    if not stripped:
        return findings

    # Try JSON format first
    if stripped.startswith("[") or stripped.startswith("{"):
        findings = _parse_json(stripped)
        if findings:
            return findings

    # Text format fallback
    findings = _parse_text(stripped)
    return findings


def _parse_json(data: str) -> list[dict]:
    """Parse WhatWeb JSON output."""
    findings = []

    # Handle JSONL or JSON array
    entries = []
    try:
        parsed = json.loads(data)
        if isinstance(parsed, list):
            entries = parsed
        elif isinstance(parsed, dict):
            entries = [parsed]
    except (json.JSONDecodeError, ValueError):
        # Try JSONL
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    entries.append(obj)
            except (json.JSONDecodeError, ValueError):
                continue

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        target = entry.get("target", "")
        plugins = entry.get("plugins", {})
        http_status = entry.get("http_status", 0)

        if not target or not plugins:
            continue

        # Build a comprehensive tech stack finding
        techs = []
        for plugin_name, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict):
                continue
            version = ""
            if "version" in plugin_data:
                ver_list = plugin_data["version"]
                if isinstance(ver_list, list) and ver_list:
                    version = ver_list[0]
                elif isinstance(ver_list, str):
                    version = ver_list

            string_info = ""
            if "string" in plugin_data:
                s = plugin_data["string"]
                if isinstance(s, list) and s:
                    string_info = s[0]
                elif isinstance(s, str):
                    string_info = s

            tech_str = plugin_name
            if version:
                tech_str += f" {version}"
            if string_info:
                tech_str += f" ({string_info})"
            techs.append(tech_str)

            # Check for security-relevant technologies
            name_lower = plugin_name.lower()
            for concern_key, (sev, desc) in _SECURITY_CONCERNS.items():
                if concern_key in name_lower:
                    findings.append(make_finding(
                        tool=TOOL_NAME,
                        title=f"Technology: {tech_str} on {target}",
                        severity=sev,
                        vuln_type="info_disclosure",
                        description=f"{desc}\nVersion: {version}" if version else desc,
                        endpoint=target,
                        host=_extract_host(target),
                        evidence=f"Detected: {tech_str}",
                        tags=["tech-detect", "whatweb", name_lower],
                        raw_data={"plugin": plugin_name, "data": plugin_data},
                    ))
                    break

        # Always emit a summary finding with full tech stack
        if techs:
            findings.append(make_finding(
                tool=TOOL_NAME,
                title=f"Technology Stack: {target}",
                severity="informational",
                vuln_type="info_disclosure",
                description=f"Technologies detected on {target}:\n" + "\n".join(f"  - {t}" for t in techs),
                endpoint=target,
                host=_extract_host(target),
                evidence="\n".join(techs),
                tags=["tech-detect", "whatweb", "summary"],
                raw_data=entry,
            ))

    return findings


def _parse_text(data: str) -> list[dict]:
    """Parse WhatWeb text output (default or verbose)."""
    findings = []

    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("WhatWeb") or line.startswith("ERROR"):
            continue

        # Default format: http://target [200 OK] Apache, ...
        if "[" in line and "]" in line:
            # Extract URL
            url = line.split("[")[0].strip()
            # Extract technologies after the status bracket
            bracket_end = line.index("]") + 1
            tech_part = line[bracket_end:].strip().lstrip(",").strip()

            if url and tech_part:
                techs = [t.strip() for t in tech_part.split(",") if t.strip()]
                findings.append(make_finding(
                    tool=TOOL_NAME,
                    title=f"Technology Stack: {url}",
                    severity="informational",
                    vuln_type="info_disclosure",
                    description=f"Technologies detected on {url}:\n" + "\n".join(f"  - {t}" for t in techs),
                    endpoint=url,
                    host=_extract_host(url),
                    evidence=tech_part,
                    tags=["tech-detect", "whatweb"],
                ))

    return findings


def _extract_host(url: str) -> str:
    """Extract hostname from URL."""
    host = url
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split(":")[0]
    return host


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
