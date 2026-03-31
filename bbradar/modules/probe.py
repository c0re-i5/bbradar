"""
Probe module — makes recon data actionable.

Queries discovered ports, services, and technologies for a target,
then suggests and optionally auto-runs follow-up tools with results
automatically ingested into the project.
"""

import sys
from collections import defaultdict

from ..core.database import get_connection
from ..core.utils import run_tool
from .recon import (
    TOOL_RUNNERS, list_recon, add_recon, _validate_target,
)


# ═══════════════════════════════════════════════════════════════════
# Port → tool mapping
# ═══════════════════════════════════════════════════════════════════

# Maps port numbers (or ranges) to suggested follow-up actions.
# Each action: (tool_name, description, extra_args_or_callable)
PORT_ACTIONS = {
    21: [("nmap", "FTP banner grab & scripts", "-sV -sC -p 21")],
    22: [("nmap", "SSH version & auth methods", "-sV -sC -p 22")],
    23: [("nmap", "Telnet banner grab", "-sV -sC -p 23")],
    25: [("nmap", "SMTP enumeration", "-sV -sC -p 25 --script smtp-commands,smtp-enum-users")],
    53: [
        ("dig", "DNS zone transfer attempt", ""),
        ("nmap", "DNS enumeration scripts", "-sV -sC -p 53 --script dns-zone-transfer"),
    ],
    80: [
        ("nikto", "Web vulnerability scan", ""),
        ("nuclei", "Template-based vuln scan", ""),
        ("gobuster", "Directory brute-force", ""),
        ("whatweb", "Technology fingerprinting", ""),
    ],
    443: [
        ("nikto", "Web vulnerability scan (HTTPS)", ""),
        ("nuclei", "Template-based vuln scan", ""),
        ("gobuster", "Directory brute-force", ""),
        ("whatweb", "Technology fingerprinting", ""),
        ("testssl", "TLS/SSL analysis", ""),
    ],
    445: [("nmap", "SMB enumeration", "-sV -p 445 --script smb-enum-shares,smb-vuln*")],
    993: [("nmap", "IMAPS enumeration", "-sV -sC -p 993")],
    1433: [("nmap", "MSSQL enumeration", "-sV -p 1433 --script ms-sql-info")],
    1521: [("nmap", "Oracle DB enumeration", "-sV -p 1521 --script oracle-sid-brute")],
    3306: [("nmap", "MySQL enumeration", "-sV -p 3306 --script mysql-info,mysql-enum")],
    3389: [("nmap", "RDP enumeration", "-sV -p 3389 --script rdp-enum-encryption")],
    5432: [("nmap", "PostgreSQL enumeration", "-sV -p 5432 --script pgsql-brute")],
    5900: [("nmap", "VNC enumeration", "-sV -p 5900 --script vnc-info")],
    6379: [("nmap", "Redis enumeration", "-sV -p 6379 --script redis-info")],
    8080: [
        ("nikto", "Web vulnerability scan (alt port)", ""),
        ("nuclei", "Template-based vuln scan", ""),
        ("gobuster", "Directory brute-force", ""),
        ("whatweb", "Technology fingerprinting", ""),
    ],
    8443: [
        ("nikto", "Web vulnerability scan (alt HTTPS)", ""),
        ("nuclei", "Template-based vuln scan", ""),
        ("testssl", "TLS/SSL analysis", ""),
        ("whatweb", "Technology fingerprinting", ""),
    ],
    27017: [("nmap", "MongoDB enumeration", "-sV -p 27017 --script mongodb-info")],
}

# HTTP-like ports that get the full web treatment
_HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000, 8081}

# Service name → tool suggestions (for when service info is available)
SERVICE_ACTIONS = {
    "http": [
        ("nikto", "Web vulnerability scan", ""),
        ("nuclei", "Template-based vuln scan", ""),
        ("gobuster", "Directory brute-force", ""),
        ("whatweb", "Technology fingerprinting", ""),
    ],
    "https": [
        ("nikto", "Web vulnerability scan", ""),
        ("nuclei", "Template-based vuln scan", ""),
        ("gobuster", "Directory brute-force", ""),
        ("whatweb", "Technology fingerprinting", ""),
        ("testssl", "TLS/SSL analysis", ""),
    ],
    "ftp": [("nmap", "FTP scripts", "-sV -sC -p 21 --script ftp-anon,ftp-bounce")],
    "ssh": [("nmap", "SSH scripts", "-sV -sC -p 22 --script ssh-auth-methods")],
    "smtp": [("nmap", "SMTP scripts", "-sV -sC --script smtp-commands,smtp-enum-users")],
    "dns": [("dig", "DNS record enumeration", "")],
    "mysql": [("nmap", "MySQL scripts", "-sV --script mysql-info,mysql-enum")],
    "postgresql": [("nmap", "PostgreSQL scripts", "-sV --script pgsql-brute")],
    "redis": [("nmap", "Redis scripts", "-sV --script redis-info")],
    "mongodb": [("nmap", "MongoDB scripts", "-sV --script mongodb-info")],
    "smb": [("nmap", "SMB scripts", "-sV --script smb-enum-shares,smb-vuln*")],
}

# Tech fingerprint → tool suggestions
TECH_ACTIONS = {
    "wordpress": [("wpscan", "WordPress vulnerability scan", "")],
    "wp-": [("wpscan", "WordPress vulnerability scan", "")],
    "joomla": [("nuclei", "Joomla template scan", "-tags joomla")],
    "drupal": [("nuclei", "Drupal template scan", "-tags drupal")],
    "php": [("nuclei", "PHP vulnerability scan", "-tags php")],
    "tomcat": [("nuclei", "Tomcat vulnerability scan", "-tags tomcat")],
    "jenkins": [("nuclei", "Jenkins vulnerability scan", "-tags jenkins")],
    "nginx": [("nuclei", "Nginx misconfiguration scan", "-tags nginx")],
    "apache": [("nuclei", "Apache vulnerability scan", "-tags apache")],
}


# ═══════════════════════════════════════════════════════════════════
# Core probe functions
# ═══════════════════════════════════════════════════════════════════

def get_target_intel(target_id: int, db_path=None) -> dict:
    """
    Gather all discovered intelligence for a target.

    Returns:
        {
            "target_id": int,
            "ports": [{"port": int, "proto": str, "service": str}],
            "services": [{"port": int, "name": str}],
            "tech": [str],
            "subdomains": [str],
            "urls": [str],
            "endpoints": [str],
            "dns": [str],
        }
    """
    intel = {
        "target_id": target_id,
        "ports": [],
        "services": [],
        "tech": [],
        "subdomains": [],
        "urls": [],
        "endpoints": [],
        "dns": [],
    }

    all_recon = list_recon(target_id=target_id, limit=10000, db_path=db_path)

    seen_ports = set()
    for entry in all_recon:
        dtype = entry.get("data_type", "")
        value = entry.get("value", "")

        if dtype == "port":
            # Format: "80/tcp" or "443/tcp"
            parts = value.split("/")
            try:
                port_num = int(parts[0])
            except (ValueError, IndexError):
                continue
            proto = parts[1] if len(parts) > 1 else "tcp"
            if port_num not in seen_ports:
                seen_ports.add(port_num)
                intel["ports"].append({"port": port_num, "proto": proto, "service": ""})

        elif dtype == "service":
            # Format: "80:http" or "443:https"
            if ":" in value:
                port_str, svc_name = value.split(":", 1)
                try:
                    port_num = int(port_str)
                except ValueError:
                    continue
                intel["services"].append({"port": port_num, "name": svc_name})
                # Update port entry with service name
                for p in intel["ports"]:
                    if p["port"] == port_num:
                        p["service"] = svc_name

        elif dtype == "tech":
            intel["tech"].append(value)

        elif dtype == "subdomain":
            intel["subdomains"].append(value)

        elif dtype == "url":
            intel["urls"].append(value)

        elif dtype == "endpoint":
            intel["endpoints"].append(value)

        elif dtype == "dns":
            intel["dns"].append(value)

    return intel


def suggest_actions(intel: dict, port_filter: int = None,
                    service_filter: str = None) -> list[dict]:
    """
    Generate a list of suggested follow-up actions based on discovered intel.

    Returns list of:
        {
            "index": int,
            "tool": str,
            "description": str,
            "reason": str,
            "extra_args": str,
            "port": int | None,
        }
    """
    suggestions = []
    seen = set()  # (tool, port_or_context) to avoid duplicates

    # 1. Port-based suggestions
    for port_info in intel["ports"]:
        port = port_info["port"]
        if port_filter is not None and port != port_filter:
            continue

        actions = PORT_ACTIONS.get(port, [])
        # If port looks HTTP-like but isn't in PORT_ACTIONS, add web tools
        if not actions and port in _HTTP_PORTS:
            actions = PORT_ACTIONS.get(80, [])

        for tool_name, desc, extra_args in actions:
            key = (tool_name, port)
            if key in seen:
                continue
            seen.add(key)
            suggestions.append({
                "tool": tool_name,
                "description": desc,
                "reason": f"Port {port}/{port_info['proto']} open",
                "extra_args": extra_args,
                "port": port,
            })

    # 2. Service-based suggestions
    for svc in intel["services"]:
        svc_name = svc["name"].lower()
        if service_filter and service_filter.lower() not in svc_name:
            continue

        for svc_key, actions in SERVICE_ACTIONS.items():
            if svc_key in svc_name:
                for tool_name, desc, extra_args in actions:
                    key = (tool_name, svc["port"])
                    if key in seen:
                        continue
                    seen.add(key)
                    suggestions.append({
                        "tool": tool_name,
                        "description": desc,
                        "reason": f"Service '{svc['name']}' on port {svc['port']}",
                        "extra_args": extra_args,
                        "port": svc["port"],
                    })

    # 3. Tech-based suggestions
    for tech in intel["tech"]:
        tech_lower = tech.lower()
        for tech_key, actions in TECH_ACTIONS.items():
            if tech_key in tech_lower:
                for tool_name, desc, extra_args in actions:
                    key = (tool_name, f"tech:{tech_key}")
                    if key in seen:
                        continue
                    seen.add(key)
                    suggestions.append({
                        "tool": tool_name,
                        "description": desc,
                        "reason": f"Technology detected: {tech}",
                        "extra_args": extra_args,
                        "port": None,
                    })

    # Number them
    for i, s in enumerate(suggestions, 1):
        s["index"] = i

    return suggestions


def run_probe_action(target_id: int, target_value: str, action: dict,
                     db_path=None) -> dict:
    """
    Execute a single probe action and return results.

    Returns:
        {"tool": str, "description": str, "count": int, "error": str | None}
    """
    tool_name = action["tool"]
    extra_args = action.get("extra_args", "")

    if tool_name not in TOOL_RUNNERS:
        return {
            "tool": tool_name,
            "description": action["description"],
            "count": 0,
            "error": f"Tool runner not available: {tool_name}",
        }

    runner_fn, _desc, _timeout = TOOL_RUNNERS[tool_name]

    # For port-specific nmap scans, use the extra_args from the action
    # which already contains -p <port>
    try:
        if tool_name == "httpx":
            count = runner_fn(target_id, targets=[target_value],
                              extra_args=extra_args, db_path=db_path)
        else:
            count = runner_fn(target_id, target_value,
                              extra_args=extra_args, db_path=db_path)
        return {
            "tool": tool_name,
            "description": action["description"],
            "count": count,
            "error": None,
        }
    except Exception as e:
        return {
            "tool": tool_name,
            "description": action["description"],
            "count": 0,
            "error": str(e),
        }


def auto_probe(target_id: int, target_value: str, intel: dict,
               port_filter: int = None, service_filter: str = None,
               db_path=None) -> list[dict]:
    """
    Auto-run all suggested actions for a target (no user interaction).
    Returns list of result dicts.
    """
    suggestions = suggest_actions(intel, port_filter=port_filter,
                                  service_filter=service_filter)
    results = []
    for action in suggestions:
        result = run_probe_action(target_id, target_value, action,
                                  db_path=db_path)
        results.append(result)
    return results
