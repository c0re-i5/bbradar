"""
Tool output parser registry.

Each parser converts raw tool output into a list of normalized
ParsedFinding dicts that the ingest pipeline can process.

Standard finding dict keys:
    tool            str     — source tool name
    title           str     — finding title
    severity        str     — critical/high/medium/low/informational
    vuln_type       str     — maps to vulns table vuln_type (xss, sqli, etc.)
    description     str     — finding description
    endpoint        str     — affected URL / endpoint / host:port
    host            str     — target hostname or IP
    port            int|None — port number if applicable
    evidence        str     — raw evidence / output snippet
    request         str     — HTTP request if available
    response        str     — HTTP response if available
    cve_id          str     — CVE identifier if known
    cwe_id          str     — CWE identifier if known
    cvss_score      float|None — CVSS score if known
    references      list[str]  — reference URLs
    tags            list[str]  — tool-specific tags
    raw_data        dict    — original parsed data for provenance
    fingerprint     str     — dedup key (auto-generated if empty)
"""

import hashlib
import json
import os
from pathlib import Path


def make_finding(*, tool: str, title: str, severity: str = "informational",
                 vuln_type: str = "", description: str = "", endpoint: str = "",
                 host: str = "", port: int | None = None, evidence: str = "",
                 request: str = "", response: str = "", cve_id: str = "",
                 cwe_id: str = "", cvss_score: float | None = None,
                 references: list[str] | None = None, tags: list[str] | None = None,
                 raw_data: dict | None = None, fingerprint: str = "") -> dict:
    """Create a standardized finding dict with defaults."""
    finding = {
        "tool": tool,
        "title": title,
        "severity": _normalize_severity(severity),
        "vuln_type": vuln_type,
        "description": description,
        "endpoint": endpoint,
        "host": host,
        "port": port,
        "evidence": evidence,
        "request": request,
        "response": response,
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "cvss_score": cvss_score,
        "references": references or [],
        "tags": tags or [],
        "raw_data": raw_data or {},
        "fingerprint": fingerprint,
    }
    if not finding["fingerprint"]:
        finding["fingerprint"] = _make_fingerprint(finding)
    return finding


def _normalize_severity(sev: str) -> str:
    """Normalize severity string to our standard scale."""
    sev = (sev or "").strip().lower()
    mapping = {
        "critical": "critical", "crit": "critical",
        "high": "high", "h": "high",
        "medium": "medium", "med": "medium", "moderate": "medium",
        "low": "low", "l": "low",
        "informational": "informational", "info": "informational",
        "none": "informational", "unknown": "informational",
    }
    return mapping.get(sev, "informational")


def _make_fingerprint(finding: dict) -> str:
    """Generate a dedup fingerprint from key fields."""
    parts = [
        finding.get("host", ""),
        str(finding.get("port", "")),
        finding.get("endpoint", ""),
        finding.get("vuln_type", ""),
        finding.get("cve_id", ""),
        finding.get("title", "")[:60],
    ]
    raw = "|".join(p.lower().strip() for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ═══════════════════════════════════════════════════════════════════
# Parser Registry
# ═══════════════════════════════════════════════════════════════════

# Maps tool name → parser module with a parse(data, filename) function
_PARSERS: dict[str, object] = {}


def register_parser(tool_name: str, module):
    """Register a parser module for a tool."""
    _PARSERS[tool_name] = module


def get_parser(tool_name: str):
    """Get a registered parser module."""
    _ensure_loaded()
    return _PARSERS.get(tool_name)


def list_parsers() -> list[str]:
    """List all registered parser names."""
    _ensure_loaded()
    return sorted(_PARSERS.keys())


_loaded = False

def _ensure_loaded():
    """Lazy-load all parser modules on first access."""
    global _loaded
    if _loaded:
        return
    _loaded = True
    from . import nuclei, nmap, nikto, burp, zap, ffuf, testssl, wpscan, semgrep, sqlmap
    from . import metasploit, acunetix, qualys, fortify, veracode
    from . import masscan, gobuster, whatweb, amass, dig
    # Each module registers itself on import


# ═══════════════════════════════════════════════════════════════════
# Auto-detection
# ═══════════════════════════════════════════════════════════════════

def detect_tool(filepath: str | None = None, data: str | None = None,
                hint: str | None = None) -> str | None:
    """
    Auto-detect which tool produced the output.

    Checks in order: explicit hint, filename patterns, content signatures.
    """
    if hint:
        _ensure_loaded()
        if hint.lower() in _PARSERS:
            return hint.lower()

    if filepath:
        fname = Path(filepath).name.lower()
        # Filename-based hints
        name_hints = {
            "nuclei": ["nuclei"],
            "nmap": ["nmap", ".gnmap"],
            "nikto": ["nikto"],
            "burp": ["burp"],
            "zap": ["zap", "owasp"],
            "ffuf": ["ffuf"],
            "testssl": ["testssl"],
            "wpscan": ["wpscan"],
            "semgrep": ["semgrep", "sarif"],
            "sqlmap": ["sqlmap"],
            "metasploit": ["metasploit", "msf", "msfconsole"],
            "acunetix": ["acunetix", "wvs"],
            "qualys": ["qualys"],
            "fortify": ["fortify", "fvdl", "fpr"],
            "veracode": ["veracode", "detailedreport"],
            "masscan": ["masscan"],
            "gobuster": ["gobuster"],
            "whatweb": ["whatweb"],
            "amass": ["amass"],
            "dig": ["dig_output", "dig_results", "dnsrecon"],
        }
        for tool, patterns in name_hints.items():
            if any(p in fname for p in patterns):
                _ensure_loaded()
                if tool in _PARSERS:
                    return tool

    # Content-based detection
    content = data
    if not content and filepath:
        try:
            with open(filepath, "r", errors="replace") as f:
                content = f.read(8192)  # first 8KB
        except (OSError, IOError):
            return None

    if not content:
        return None

    _ensure_loaded()

    # Ordered by specificity (most unique signatures first)
    signatures = [
        ("nuclei", ['"template-id"', '"template"', '"matcher-name"', '"matched-at"']),
        ("burp", ['<issues burpVersion=', '<issue>', '<type>',
                   '<?xml', "<items", "<item><url>"]),
        ("zap", ['"@version"', '"site"', '"alerts"', '"alertRef"']),
        ("nmap", ['<nmaprun', 'Nmap done', '<?xml', '<host starttime=']),
        ("wpscan", ['"interesting_findings"', '"wp_version"', '"target_url"', '"effective_url"']),
        ("testssl", ['"id"', '"severity"', '"finding"', '"ip"', '"cve"']),
        ("semgrep", ['"results"', '"check_id"', '"path"', '"start"', '"end"', '"extra"']),
        ("nikto", ['"host"', '"ip"', '"port"', '"Nikto"', 'OSVDB-']),
        ("ffuf", ['"commandline"', '"results"', '"input"', '"FUZZ"', '"status"']),
        ("sqlmap", ["sqlmap", "[INFO]", "---", "Parameter:", "Type:", "Payload:"]),
        ("metasploit", ["<MetasploitV", "RHOSTS", "msf", "exploit(", "auxiliary("]),
        ("acunetix", ["<ScanGroup", "<ReportItem", "Acunetix", "<Scan>", "<ReportItems>"]),
        ("qualys", ["<ASSET_DATA_REPORT", "<WAS_SCAN_REPORT", "QID", "VULN_INFO_LIST"]),
        ("fortify", ["<FVDL", "<Vulnerabilities>", "<ClassInfo>", "Kingdom", "Fortify"]),
        ("veracode", ["<detailedreport", "<severity>", "<flaw ", "cweid=", "Veracode"]),
        ("masscan", ['"ip"', '"ports"', '"proto"', '"status"', "open tcp", "open udp"]),
        ("gobuster", ["Gobuster", "Status:", "[Size:", "Dir found:", "/admin", "directory-brute"]),
        ("whatweb", ["WhatWeb", "HTTPServer", "IP[", "Country[", "X-Powered-By"]),
        ("amass", ['"name"', '"domain"', '"addresses"', '"sources"', "OWASP Amass"]),
    ]

    # For XML, try specific root elements
    stripped = content.strip()
    if stripped.startswith("<?xml") or stripped.startswith("<"):
        if "<nmaprun" in content:
            return "nmap"
        if "burpVersion" in content or ("<issues" in content and "<type>" in content):
            return "burp"
        if "<OWASPZAPReport" in content or ("<site" in content and "<alerts" in content):
            return "zap"

    # For JSON/JSONL, try parsing first line
    first_line = content.split("\n")[0].strip()
    if first_line.startswith("{"):
        try:
            obj = json.loads(first_line)
            if isinstance(obj, dict):
                keys = set(obj.keys())
                if "template-id" in keys or "matched-at" in keys or "matcher-name" in keys:
                    return "nuclei"
                if "interesting_findings" in keys or "wp_version" in keys:
                    return "wpscan"
                if "results" in keys and "check_id" in str(obj.get("results", "")[:200] if isinstance(obj.get("results"), str) else ""):
                    return "semgrep"
        except (json.JSONDecodeError, ValueError):
            pass

    # Try bracket for JSON array
    if first_line.startswith("["):
        try:
            arr = json.loads(content[:4096])
            if arr and isinstance(arr[0], dict):
                keys = set(arr[0].keys())
                if "template-id" in keys or "matched-at" in keys:
                    return "nuclei"
        except (json.JSONDecodeError, ValueError):
            pass

    # Signature matching (count hits)
    best_tool = None
    best_score = 0
    for tool, sigs in signatures:
        score = sum(1 for s in sigs if s in content)
        if score > best_score and score >= 2:
            best_score = score
            best_tool = tool

    return best_tool
