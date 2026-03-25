"""
HackerOne API integration.

Connects BBRadar to HackerOne for program discovery, scope import,
report tracking, and earnings monitoring.

API docs: https://api.hackerone.com/reference
Auth: HTTP Basic (username, api_token)
Rate limit: 600 requests/minute
"""

import json
import os
from base64 import b64encode
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from ..core.audit import log_action
from ..core.config import load_config, set_config_value

API_BASE = "https://api.hackerone.com/v1/hackers"

# HackerOne asset type → BBRadar asset type
H1_ASSET_TYPE_MAP = {
    "URL": "url",
    "CIDR": "cidr",
    "DOMAIN": "domain",
    "WILDCARD": "wildcard",
    "IP_ADDRESS": "ip",
    "SOURCE_CODE": "other",
    "DOWNLOADABLE_EXECUTABLES": "other",
    "HARDWARE": "other",
    "OTHER": "other",
    "SMART_CONTRACT": "other",
    "AI_MODEL": "other",
    "GOOGLE_PLAY_APP_ID": "mobile_app",
    "APPLE_STORE_APP_ID": "mobile_app",
    "OTHER_IPA": "mobile_app",
    "OTHER_APK": "mobile_app",
    "WINDOWS_APP_STORE_APP_ID": "other",
    "API": "api",
}

# H1 report states → BBRadar vuln statuses
H1_STATE_MAP = {
    "new": "new",
    "triaged": "confirmed",
    "needs-more-info": "reported",
    "resolved": "resolved",
    "not-applicable": "wontfix",
    "informative": "wontfix",
    "duplicate": "duplicate",
    "spam": "wontfix",
}


# ═══════════════════════════════════════════════════════════════════
# HTTP helpers
# ═══════════════════════════════════════════════════════════════════

def _get_credentials(cfg=None):
    """Get H1 API credentials from env vars (preferred) or config file."""
    username = os.environ.get("BBRADAR_H1_USERNAME", "")
    token = os.environ.get("BBRADAR_H1_API_TOKEN", "")
    if username and token:
        return username, token
    cfg = cfg or load_config()
    h1 = cfg.get("hackerone", {})
    username = h1.get("username", "")
    token = h1.get("api_token", "")
    if not username or not token:
        raise ValueError(
            "HackerOne credentials not configured.\n"
            "Set BBRADAR_H1_USERNAME and BBRADAR_H1_API_TOKEN env vars, "
            "or run: bb h1 auth"
        )
    return username, token


def _api_request(endpoint, params=None, credentials=None):
    """Make an authenticated GET request to the HackerOne API."""
    if credentials:
        username, token = credentials
    else:
        username, token = _get_credentials()

    url = f"{API_BASE}/{endpoint}"
    if params:
        url += "?" + urlencode(params, doseq=True)

    auth_str = b64encode(f"{username}:{token}".encode()).decode()

    req = Request(url)
    req.add_header("Authorization", f"Basic {auth_str}")
    req.add_header("Accept", "application/json")

    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as e:
        if e.code == 401:
            raise ValueError(
                "Authentication failed. Check your HackerOne credentials."
            ) from None
        if e.code == 403:
            raise ValueError(
                "Access forbidden. Your API token may lack required permissions."
            ) from None
        if e.code == 429:
            raise ValueError(
                "Rate limited. Wait a moment and try again."
            ) from None
        body = ""
        try:
            body = e.read().decode()[:200]
        except Exception:
            pass
        raise RuntimeError(f"HackerOne API error {e.code}: {body}") from None
    except URLError as e:
        raise RuntimeError(f"Network error: {e.reason}") from None


def _paginate(endpoint, params=None, max_pages=10):
    """Fetch all pages from a paginated H1 API endpoint."""
    if params is None:
        params = {}
    params.setdefault("page[size]", "100")

    all_data = []
    page = 1

    while page <= max_pages:
        params["page[number]"] = str(page)
        result = _api_request(endpoint, params)
        data = result.get("data", [])
        if not data:
            break
        all_data.extend(data)

        links = result.get("links", {})
        if not links.get("next"):
            break
        page += 1

    return all_data


# ═══════════════════════════════════════════════════════════════════
# Authentication
# ═══════════════════════════════════════════════════════════════════

def configure_auth(username: str, api_token: str) -> bool:
    """Store H1 credentials and verify they work."""
    _api_request("me/reports", {"page[size]": "1"},
                 credentials=(username, api_token))
    set_config_value("hackerone.username", username)
    set_config_value("hackerone.api_token", api_token)
    return True


def check_auth() -> dict:
    """Check if H1 credentials are configured and valid."""
    cfg = load_config()
    h1 = cfg.get("hackerone", {})
    username = h1.get("username", "")
    token = h1.get("api_token", "")

    if not username or not token:
        return {"configured": False, "valid": False, "username": ""}

    try:
        _api_request("me/reports", {"page[size]": "1"})
        return {"configured": True, "valid": True, "username": username}
    except Exception:
        return {"configured": True, "valid": False, "username": username}


# ═══════════════════════════════════════════════════════════════════
# Programs
# ═══════════════════════════════════════════════════════════════════

def list_programs(offers_bounties: bool = None) -> list[dict]:
    """List programs the hacker has access to."""
    params = {}
    if offers_bounties is not None:
        params["filter[offers_bounties]"] = "true" if offers_bounties else "false"

    raw = _paginate("programs", params)

    programs = []
    for item in raw:
        attrs = item.get("attributes", {})
        programs.append({
            "id": item.get("id"),
            "handle": attrs.get("handle", ""),
            "name": attrs.get("name", ""),
            "url": f"https://hackerone.com/{attrs.get('handle', '')}",
            "offers_bounties": attrs.get("offers_bounties", False),
            "state": attrs.get("state", ""),
            "started_accepting_at": attrs.get("started_accepting_at", ""),
            "submission_state": attrs.get("submission_state", ""),
            "bookmarked": attrs.get("bookmarked", False),
        })

    return programs


def get_program(handle: str) -> dict:
    """Get detailed program information including scope."""
    result = _api_request(f"programs/{quote(handle, safe='')}")
    item = result.get("data", {})
    attrs = item.get("attributes", {})
    relationships = item.get("relationships", {})

    scopes = []
    scope_data = relationships.get("structured_scopes", {}).get("data", [])
    for s in scope_data:
        s_attrs = s.get("attributes", {})
        scopes.append({
            "asset_identifier": s_attrs.get("asset_identifier", ""),
            "asset_type": s_attrs.get("asset_type", ""),
            "eligible_for_bounty": s_attrs.get("eligible_for_bounty", False),
            "eligible_for_submission": s_attrs.get("eligible_for_submission", True),
            "instruction": s_attrs.get("instruction", ""),
            "max_severity": s_attrs.get("max_severity", ""),
        })

    return {
        "id": item.get("id"),
        "handle": attrs.get("handle", ""),
        "name": attrs.get("name", ""),
        "url": f"https://hackerone.com/{attrs.get('handle', '')}",
        "offers_bounties": attrs.get("offers_bounties", False),
        "policy": attrs.get("policy", ""),
        "state": attrs.get("state", ""),
        "scopes": scopes,
    }


def import_program(handle: str, db_path=None) -> dict:
    """
    Import a H1 program as a BBRadar project with scope rules and targets.

    Returns {project_id, targets_added, scope_rules_added}.
    """
    from .projects import create_project, get_project
    from .scope import add_rule
    from .targets import add_target

    program = get_program(handle)

    existing = get_project(name=program["name"], db_path=db_path)
    if existing:
        raise ValueError(
            f"Project '{program['name']}' already exists (ID: {existing['id']}). "
            f"Use 'bb h1 scope-sync' to update scope."
        )

    pid = create_project(
        name=program["name"],
        platform="hackerone",
        program_url=program["url"],
        scope_raw=program.get("policy", ""),
        db_path=db_path,
    )

    targets_added = 0
    rules_added = 0

    for s in program.get("scopes", []):
        asset = s["asset_identifier"]
        asset_type = H1_ASSET_TYPE_MAP.get(s["asset_type"], "other")
        in_scope = s.get("eligible_for_submission", True)

        try:
            add_target(pid, asset_type, asset, in_scope=in_scope, db_path=db_path)
            targets_added += 1
        except Exception:
            pass

        try:
            add_rule(pid, asset, rule_type="include" if in_scope else "exclude",
                     source="hackerone", db_path=db_path)
            rules_added += 1
        except Exception:
            pass

    log_action("imported_program", "hackerone", pid,
               {"handle": handle, "targets": targets_added, "rules": rules_added},
               db_path)

    return {
        "project_id": pid,
        "targets_added": targets_added,
        "scope_rules_added": rules_added,
    }


def sync_scope(project_id: int, handle: str, db_path=None) -> dict:
    """
    Sync scope from a H1 program into an existing BBRadar project.
    Adds new targets/rules without removing existing ones.
    """
    from .scope import add_rule, list_rules
    from .targets import add_target, list_targets

    program = get_program(handle)

    existing_targets = {t["value"] for t in list_targets(project_id, db_path=db_path)}
    existing_rules = {r["pattern"] for r in list_rules(project_id, db_path=db_path)}

    new_targets = 0
    new_rules = 0

    for s in program.get("scopes", []):
        asset = s["asset_identifier"]
        asset_type = H1_ASSET_TYPE_MAP.get(s["asset_type"], "other")
        in_scope = s.get("eligible_for_submission", True)

        if asset not in existing_targets:
            try:
                add_target(project_id, asset_type, asset, in_scope=in_scope,
                           db_path=db_path)
                new_targets += 1
            except Exception:
                pass

        if asset not in existing_rules:
            try:
                rule_type = "include" if in_scope else "exclude"
                add_rule(project_id, asset, rule_type=rule_type,
                         source="hackerone", db_path=db_path)
                new_rules += 1
            except Exception:
                pass

    log_action("synced_scope", "hackerone", project_id,
               {"handle": handle, "new_targets": new_targets, "new_rules": new_rules},
               db_path)

    return {"new_targets": new_targets, "new_rules": new_rules}


# ═══════════════════════════════════════════════════════════════════
# Reports
# ═══════════════════════════════════════════════════════════════════

def list_reports(state: str = None, program: str = None) -> list[dict]:
    """List the hacker's submitted reports."""
    params = {}
    if state:
        params["filter[state][]"] = state
    if program:
        params["filter[program][]"] = program

    raw = _paginate("me/reports", params)

    h1_reports = []
    for item in raw:
        attrs = item.get("attributes", {})
        h1_reports.append({
            "id": item.get("id"),
            "title": attrs.get("title", ""),
            "state": attrs.get("state", ""),
            "substate": attrs.get("substate", ""),
            "severity_rating": attrs.get("severity_rating", ""),
            "bounty_awarded_at": attrs.get("bounty_awarded_at"),
            "created_at": attrs.get("created_at", ""),
            "disclosed_at": attrs.get("disclosed_at"),
            "triaged_at": attrs.get("triaged_at"),
            "closed_at": attrs.get("closed_at"),
            "url": f"https://hackerone.com/reports/{item.get('id', '')}",
        })

    return h1_reports


def get_report(report_id: str) -> dict:
    """Get detailed report information."""
    result = _api_request(f"me/reports/{quote(str(report_id), safe='')}")
    item = result.get("data", {})
    attrs = item.get("attributes", {})

    return {
        "id": item.get("id"),
        "title": attrs.get("title", ""),
        "state": attrs.get("state", ""),
        "substate": attrs.get("substate", ""),
        "severity_rating": attrs.get("severity_rating", ""),
        "vulnerability_information": attrs.get("vulnerability_information", ""),
        "impact": attrs.get("impact", ""),
        "created_at": attrs.get("created_at", ""),
        "triaged_at": attrs.get("triaged_at"),
        "bounty_awarded_at": attrs.get("bounty_awarded_at"),
        "closed_at": attrs.get("closed_at"),
        "disclosed_at": attrs.get("disclosed_at"),
        "url": f"https://hackerone.com/reports/{item.get('id', '')}",
    }


# ═══════════════════════════════════════════════════════════════════
# Earnings & Balance
# ═══════════════════════════════════════════════════════════════════

def get_balance() -> dict:
    """Get current HackerOne balance."""
    result = _api_request("me/balance")
    data = result.get("data", {})
    attrs = data.get("attributes", {})
    return {
        "balance": attrs.get("balance", "0.00"),
        "currency": attrs.get("currency", "USD"),
    }


def get_earnings(sort: str = "-awarded_at") -> list[dict]:
    """Get earnings history."""
    raw = _paginate("me/earnings", {"sort": sort})

    earnings = []
    for item in raw:
        attrs = item.get("attributes", {})
        earnings.append({
            "id": item.get("id"),
            "amount": attrs.get("amount", "0.00"),
            "currency": attrs.get("currency", "USD"),
            "awarded_at": attrs.get("awarded_at", ""),
            "bounty_type": attrs.get("bounty_type", ""),
        })

    return earnings


def get_earnings_summary() -> dict:
    """Calculate earnings summary statistics."""
    all_earnings = get_earnings()

    total = sum(float(e.get("amount", 0)) for e in all_earnings)
    count = len(all_earnings)
    avg = total / count if count > 0 else 0

    by_month = {}
    for e in all_earnings:
        month = e.get("awarded_at", "")[:7]  # YYYY-MM
        if month:
            by_month[month] = by_month.get(month, 0) + float(e.get("amount", 0))

    return {
        "total_earned": total,
        "total_bounties": count,
        "average_bounty": avg,
        "currency": "USD",
        "by_month": dict(sorted(by_month.items(), reverse=True)),
    }


# ═══════════════════════════════════════════════════════════════════
# Program Discovery
# ═══════════════════════════════════════════════════════════════════

def search_programs(query: str = None, asset_type: str = None,
                    bounties_only: bool = True) -> list[dict]:
    """
    Search for bug bounty programs.

    Args:
        query: Text to match in program name/handle
        asset_type: Filter by H1 asset type (URL, DOMAIN, etc.)
        bounties_only: Only show programs that pay bounties
    """
    params = {}
    if bounties_only:
        params["filter[offers_bounties]"] = "true"
    if asset_type:
        params["filter[asset_type]"] = asset_type

    raw = _paginate("programs", params)

    results = []
    for item in raw:
        attrs = item.get("attributes", {})
        name = attrs.get("name", "")
        handle = attrs.get("handle", "")

        if query:
            q = query.lower()
            if q not in name.lower() and q not in handle.lower():
                continue

        results.append({
            "handle": handle,
            "name": name,
            "url": f"https://hackerone.com/{handle}",
            "offers_bounties": attrs.get("offers_bounties", False),
            "state": attrs.get("state", ""),
            "submission_state": attrs.get("submission_state", ""),
            "started_accepting_at": attrs.get("started_accepting_at", ""),
        })

    return results


# ═══════════════════════════════════════════════════════════════════
# Dashboard
# ═══════════════════════════════════════════════════════════════════

def get_dashboard_data(db_path=None) -> dict:
    """
    Aggregate data for the dashboard view.
    Combines local BBRadar data with H1 API data (if configured).
    """
    from .projects import get_project_stats, list_projects
    from .vulns import get_vuln_stats

    dashboard = {"local": {}, "hackerone": {}}

    # Local data
    proj_list = list_projects(db_path=db_path)
    active = [p for p in proj_list if p["status"] == "active"]

    total_vulns = 0
    total_bounty = 0
    vulns_by_severity = {}
    vulns_by_status = {}

    for p in proj_list:
        stats = get_vuln_stats(p["id"], db_path)
        total_vulns += stats["total"]
        total_bounty += stats.get("total_bounty", 0)
        for sev, cnt in stats.get("by_severity", {}).items():
            vulns_by_severity[sev] = vulns_by_severity.get(sev, 0) + cnt
        for st, cnt in stats.get("by_status", {}).items():
            vulns_by_status[st] = vulns_by_status.get(st, 0) + cnt

    dashboard["local"] = {
        "total_projects": len(proj_list),
        "active_projects": len(active),
        "total_vulns": total_vulns,
        "vulns_by_severity": vulns_by_severity,
        "vulns_by_status": vulns_by_status,
        "local_bounty_total": total_bounty,
        "projects": [
            {"id": p["id"], "name": p["name"], "status": p["status"]}
            for p in active[:10]
        ],
    }

    # HackerOne data (if configured)
    try:
        auth = check_auth()
        if auth["valid"]:
            balance = get_balance()
            h1_reports = list_reports()

            report_states = {}
            for r in h1_reports:
                st = r.get("state", "unknown")
                report_states[st] = report_states.get(st, 0) + 1

            dashboard["hackerone"] = {
                "connected": True,
                "username": auth["username"],
                "balance": balance.get("balance", "0.00"),
                "currency": balance.get("currency", "USD"),
                "total_reports": len(h1_reports),
                "report_states": report_states,
            }
        else:
            dashboard["hackerone"] = {"connected": False}
    except Exception:
        dashboard["hackerone"] = {"connected": False}

    return dashboard
