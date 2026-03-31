"""
Amass output parser.

Handles Amass JSON output (amass enum -json) and plain text output.
Extracts discovered subdomains, IP addresses, and DNS records.
"""

import json
from . import register_parser, make_finding

TOOL_NAME = "amass"


def parse(data: str, filename: str = "") -> list[dict]:
    """Parse amass output into findings."""
    findings = []

    stripped = data.strip()
    if not stripped:
        return findings

    # Try JSON/JSONL format first (amass -json)
    if stripped.startswith("{") or stripped.startswith("["):
        findings = _parse_json(stripped)
        if findings:
            return findings

    # Plain text: one subdomain per line
    findings = _parse_text(stripped)
    return findings


def _parse_json(data: str) -> list[dict]:
    """Parse amass JSON/JSONL output."""
    findings = []
    seen = set()

    entries = []
    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, list):
                entries.extend(obj)
            elif isinstance(obj, dict):
                entries.append(obj)
        except (json.JSONDecodeError, ValueError):
            continue

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        name = entry.get("name", "")
        domain = entry.get("domain", "")
        addresses = entry.get("addresses", [])
        sources = entry.get("sources", [])
        tag = entry.get("tag", "")

        if not name or name in seen:
            continue
        seen.add(name)

        # Build IP list
        ip_list = []
        if isinstance(addresses, list):
            for addr in addresses:
                if isinstance(addr, dict):
                    ip = addr.get("ip", "")
                    if ip:
                        ip_list.append(ip)
                elif isinstance(addr, str):
                    ip_list.append(addr)

        source_list = sources if isinstance(sources, list) else []

        description = f"Subdomain discovered: {name}"
        if domain:
            description += f"\nParent domain: {domain}"
        if ip_list:
            description += f"\nResolved IPs: {', '.join(ip_list)}"
        if source_list:
            description += f"\nSources: {', '.join(source_list)}"
        if tag:
            description += f"\nDiscovery method: {tag}"

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=f"Subdomain: {name}",
            severity="informational",
            vuln_type="info_disclosure",
            description=description,
            endpoint=name,
            host=name,
            evidence=f"Subdomain: {name}" + (f" → {', '.join(ip_list)}" if ip_list else ""),
            tags=["subdomain", "amass"] + ([tag] if tag else []),
            raw_data=entry,
        ))

    return findings


def _parse_text(data: str) -> list[dict]:
    """Parse amass plain text output (one subdomain per line)."""
    findings = []
    seen = set()

    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Skip amass banner/status lines
        if any(kw in line for kw in ["Enumeration", "OWASP", "---", "Querying", "discoveries"]):
            continue

        # May contain: subdomain or "subdomain (ip)"
        parts = line.split()
        name = parts[0] if parts else ""
        if not name or name in seen:
            continue

        # Basic domain validation
        if "." not in name:
            continue
        seen.add(name)

        findings.append(make_finding(
            tool=TOOL_NAME,
            title=f"Subdomain: {name}",
            severity="informational",
            vuln_type="info_disclosure",
            description=f"Subdomain discovered: {name}",
            endpoint=name,
            host=name,
            evidence=f"Subdomain: {name}",
            tags=["subdomain", "amass"],
        ))

    return findings


register_parser(TOOL_NAME, __import__(__name__, fromlist=[""]))
