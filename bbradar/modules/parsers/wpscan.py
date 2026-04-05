"""
WPScan JSON output parser.

Handles WPScan JSON output (--format json).
Parses WordPress core, plugin, theme, and user enumeration findings.
"""

import json
import logging
from . import register_parser, make_finding

logger = logging.getLogger(__name__)

TOOL_NAME = "wpscan"

_VULN_TYPE_MAP = {
    "sqli": "sqli",
    "xss": "xss",
    "rce": "rce",
    "rfi": "rfi",
    "lfi": "lfi",
    "authbypass": "auth_bypass",
    "bypass": "auth_bypass",
    "upload": "file_upload",
    "dos": "misconfiguration",
    "csrf": "csrf",
    "ssrf": "ssrf",
    "privesc": "privilege_escalation",
    "code execution": "rce",
    "arbitrary file": "path_traversal",
    "object injection": "deserialization",
    "redirect": "open_redirect",
}


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse WPScan JSON output."""
    findings = []

    try:
        parsed = json.loads(data)
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse %s JSON output: %s", TOOL_NAME, e)
        return findings

    if not isinstance(parsed, dict):
        return findings

    target_url = parsed.get("target_url", "")
    host = ""
    if target_url:
        from urllib.parse import urlparse
        p = urlparse(target_url)
        host = p.hostname or ""

    # WordPress version
    version_info = parsed.get("version", {})
    if version_info and isinstance(version_info, dict):
        wp_ver = version_info.get("number", "")
        status = version_info.get("status", "")
        vulns = version_info.get("vulnerabilities", [])

        if status == "insecure":
            findings.append(make_finding(
                tool=TOOL_NAME,
                title=f"WordPress {wp_ver} — outdated/insecure",
                severity="high",
                vuln_type="misconfiguration",
                description=f"WordPress version {wp_ver} is marked as insecure.",
                endpoint=target_url,
                host=host,
                tags=["wpscan", "wordpress", "outdated"],
            ))

        for vuln in vulns:
            f = _parse_vuln(vuln, f"WordPress Core {wp_ver}", target_url, host)
            if f:
                findings.append(f)

    # Main theme
    main_theme = parsed.get("main_theme", {})
    if main_theme and isinstance(main_theme, dict):
        _parse_component(main_theme, "theme", target_url, host, findings)

    # Plugins
    plugins = parsed.get("plugins", {})
    if isinstance(plugins, dict):
        for slug, plugin_data in plugins.items():
            if isinstance(plugin_data, dict):
                _parse_component(plugin_data, "plugin", target_url, host, findings)

    # Themes (beyond main)
    themes = parsed.get("themes", {})
    if isinstance(themes, dict):
        for slug, theme_data in themes.items():
            if isinstance(theme_data, dict):
                _parse_component(theme_data, "theme", target_url, host, findings)

    # Users
    users = parsed.get("users", {})
    if isinstance(users, dict) and users:
        user_list = ", ".join(list(users.keys())[:10])
        findings.append(make_finding(
            tool=TOOL_NAME,
            title=f"WordPress user enumeration: {user_list}",
            severity="low",
            vuln_type="info_disclosure",
            description=f"Enumerated {len(users)} WordPress user(s): {user_list}",
            endpoint=target_url,
            host=host,
            tags=["wpscan", "wordpress", "user-enumeration"],
        ))

    # Interesting findings
    for item in parsed.get("interesting_findings", []):
        if not isinstance(item, dict):
            continue
        url = item.get("url", "")
        type_str = item.get("type", "")
        to_s = item.get("to_s", "")
        refs = item.get("references", {})
        ref_urls = _extract_refs(refs)

        if "xmlrpc" in (url + to_s).lower():
            findings.append(make_finding(
                tool=TOOL_NAME,
                title=f"WordPress XML-RPC enabled at {url}",
                severity="low",
                vuln_type="misconfiguration",
                description=to_s or f"XML-RPC interface found at {url}",
                endpoint=url,
                host=host,
                references=ref_urls,
                tags=["wpscan", "wordpress", "xmlrpc"],
            ))
        elif "readme" in (url + to_s).lower() or "debug" in (url + to_s).lower():
            findings.append(make_finding(
                tool=TOOL_NAME,
                title=f"WordPress info disclosure: {to_s[:80] or url}",
                severity="informational",
                vuln_type="info_disclosure",
                description=to_s or f"Interesting finding at {url}",
                endpoint=url,
                host=host,
                references=ref_urls,
                tags=["wpscan", "wordpress"],
            ))

    return findings


def _parse_component(comp: dict, comp_type: str, target_url: str, host: str, findings: list):
    """Parse a plugin or theme component."""
    slug = comp.get("slug", "unknown")
    version = comp.get("version", {})
    ver_num = version.get("number", "") if isinstance(version, dict) else str(version)
    outdated = comp.get("outdated", False)
    vulns = comp.get("vulnerabilities", [])

    label = f"{comp_type.title()} '{slug}'" + (f" v{ver_num}" if ver_num else "")

    if outdated:
        findings.append(make_finding(
            tool=TOOL_NAME,
            title=f"Outdated WordPress {label}",
            severity="medium",
            vuln_type="misconfiguration",
            description=f"WordPress {label} is outdated. Latest version available.",
            endpoint=target_url,
            host=host,
            tags=["wpscan", "wordpress", comp_type, "outdated"],
        ))

    for vuln in vulns:
        f = _parse_vuln(vuln, label, target_url, host)
        if f:
            findings.append(f)


def _parse_vuln(vuln: dict, component: str, target_url: str, host: str) -> dict | None:
    """Parse a WPScan vulnerability entry."""
    if not isinstance(vuln, dict):
        return None

    title = vuln.get("title", "")
    fixed_in = vuln.get("fixed_in", "")
    refs = vuln.get("references", {})
    ref_urls = _extract_refs(refs)
    vuln_type_raw = vuln.get("vuln_type", "")

    # Extract CVE
    cve_id = ""
    cve_list = refs.get("cve", []) if isinstance(refs, dict) else []
    if cve_list:
        cve_id = f"CVE-{cve_list[0]}" if not str(cve_list[0]).startswith("CVE") else str(cve_list[0])

    # Classify
    vuln_type = _classify(title, vuln_type_raw)

    desc = f"{component}: {title}"
    if fixed_in:
        desc += f"\nFixed in version: {fixed_in}"

    # Derive severity from vuln type keywords
    severity = "high"
    combined_lower = f"{title} {vuln_type_raw}".lower()
    if any(k in combined_lower for k in ("rce", "remote code", "deserialization", "sql injection")):
        severity = "critical"
    elif any(k in combined_lower for k in ("info", "disclosure", "version", "readme", "enumer")):
        severity = "medium"

    return make_finding(
        tool=TOOL_NAME,
        title=f"WPScan: {title[:80]}",
        severity=severity,
        vuln_type=vuln_type,
        description=desc,
        endpoint=target_url,
        host=host,
        cve_id=cve_id,
        references=ref_urls,
        tags=["wpscan", "wordpress"],
        raw_data=vuln,
    )


def _classify(title: str, vuln_type_raw: str) -> str:
    combined = f"{title} {vuln_type_raw}".lower()
    for keyword, vtype in _VULN_TYPE_MAP.items():
        if keyword in combined:
            return vtype
    return "known_cve"


def _extract_refs(refs) -> list[str]:
    """Extract URL references from WPScan refs structure."""
    urls = []
    if not isinstance(refs, dict):
        return urls
    for key, val_list in refs.items():
        if key == "url" and isinstance(val_list, list):
            urls.extend(str(v) for v in val_list)
        elif key == "wpvulndb" and isinstance(val_list, list):
            urls.extend(f"https://wpscan.com/vulnerability/{v}" for v in val_list)
    return urls


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
