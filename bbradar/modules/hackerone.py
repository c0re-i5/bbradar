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


# ═══════════════════════════════════════════════════════════════════
# Program Cache & Filtering
# ═══════════════════════════════════════════════════════════════════

CACHE_MAX_AGE_HOURS = 24


def refresh_program_cache(db_path=None) -> int:
    """Fetch all programs from H1 and store in local cache. Returns count."""
    from ..core.database import get_connection

    programs = list_programs()

    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM h1_program_cache")
        for p in programs:
            conn.execute(
                """INSERT INTO h1_program_cache
                   (h1_id, handle, name, offers_bounties, state,
                    started_accepting_at, submission_state, bookmarked)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (p["id"], p["handle"], p["name"],
                 1 if p["offers_bounties"] else 0,
                 p["state"], p["started_accepting_at"],
                 p["submission_state"],
                 1 if p["bookmarked"] else 0),
            )

    log_action("program_cache_refreshed", "hackerone", None,
               {"count": len(programs)}, db_path)
    return len(programs)


def _cache_is_fresh(db_path=None) -> bool:
    """Check if the cache exists and is less than CACHE_MAX_AGE_HOURS old."""
    from ..core.database import get_connection
    with get_connection(db_path) as conn:
        row = conn.execute(
            """SELECT MIN(cached_at) as oldest FROM h1_program_cache"""
        ).fetchone()
        if not row or not row["oldest"]:
            return False
        # Check if oldest entry is within the cache age limit
        count = conn.execute(
            f"""SELECT COUNT(*) as cnt FROM h1_program_cache
                WHERE cached_at > datetime('now', '-{int(CACHE_MAX_AGE_HOURS)} hours')"""
        ).fetchone()
        return count["cnt"] > 0


def get_cached_programs(
    bounties_only: bool = False,
    sort: str = "name",
    search: str = None,
    state: str = None,
    refresh: bool = False,
    db_path=None,
) -> dict:
    """
    Get programs from cache with filters. Auto-refreshes if cache is stale.

    Args:
        bounties_only: Only show programs that pay bounties
        sort: Sort by 'name', 'newest', 'handle'
        search: Filter by keyword in name or handle
        state: Filter by program state
        refresh: Force refresh from API

    Returns: {programs: [...], from_cache: bool, total: int, filtered: int}
    """
    from ..core.database import get_connection

    if refresh or not _cache_is_fresh(db_path):
        refresh_program_cache(db_path)
        from_cache = False
    else:
        from_cache = True

    # Build query with filters
    conditions = []
    params = []

    if bounties_only:
        conditions.append("offers_bounties = 1")

    if state:
        conditions.append("state = ?")
        params.append(state)

    if search:
        conditions.append("(handle LIKE ? OR name LIKE ?)")
        term = f"%{search}%"
        params.extend([term, term])

    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

    # Sort
    order_map = {
        "name": "name ASC",
        "handle": "handle ASC",
        "newest": "started_accepting_at DESC",
    }
    order = order_map.get(sort, "name ASC")

    with get_connection(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) as cnt FROM h1_program_cache").fetchone()["cnt"]
        rows = conn.execute(
            f"SELECT * FROM h1_program_cache{where} ORDER BY {order}", params
        ).fetchall()

    programs = []
    for r in rows:
        programs.append({
            "id": r["h1_id"],
            "handle": r["handle"],
            "name": r["name"],
            "url": f"https://hackerone.com/{r['handle']}",
            "offers_bounties": bool(r["offers_bounties"]),
            "state": r["state"],
            "started_accepting_at": r["started_accepting_at"] or "",
            "submission_state": r["submission_state"],
            "bookmarked": bool(r["bookmarked"]),
        })

    return {
        "programs": programs,
        "from_cache": from_cache,
        "total": total,
        "filtered": len(programs),
    }


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
        "name": attrs.get("name", "") or attrs.get("handle", handle),
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

    # Link the H1 handle to the project
    from ..core.database import get_connection
    with get_connection(db_path) as conn:
        conn.execute("UPDATE projects SET h1_handle = ? WHERE id = ?",
                     (handle, pid))

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


# ═══════════════════════════════════════════════════════════════════
# Scope Change Detection (Watch)
# ═══════════════════════════════════════════════════════════════════

def watch_program(handle: str, db_path=None) -> dict:
    """
    Add a program to the watchlist and take an initial scope snapshot.
    Links to existing project if one was imported from this handle.
    Returns {handle, name, scopes_snapshotted, project_id}.
    """
    from ..core.database import get_connection

    program = get_program(handle)

    with get_connection(db_path) as conn:
        # Check for linked project
        row = conn.execute(
            "SELECT id FROM projects WHERE h1_handle = ?", (handle,)
        ).fetchone()
        project_id = row["id"] if row else None

        # Insert or update watched program
        conn.execute(
            """INSERT INTO h1_watched_programs (handle, name, project_id, last_checked_at)
               VALUES (?, ?, ?, datetime('now'))
               ON CONFLICT(handle) DO UPDATE SET
                   name = excluded.name,
                   project_id = COALESCE(excluded.project_id, h1_watched_programs.project_id),
                   last_checked_at = datetime('now')""",
            (handle, program["name"], project_id),
        )

        # Take initial snapshot — replace any existing
        conn.execute("DELETE FROM h1_scope_snapshots WHERE handle = ?", (handle,))
        count = 0
        for s in program.get("scopes", []):
            conn.execute(
                """INSERT INTO h1_scope_snapshots
                   (handle, asset_identifier, asset_type, eligible_for_bounty,
                    eligible_for_submission, max_severity, instruction)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (handle, s["asset_identifier"], s["asset_type"],
                 1 if s.get("eligible_for_bounty") else 0,
                 1 if s.get("eligible_for_submission", True) else 0,
                 s.get("max_severity", ""),
                 s.get("instruction", "")),
            )
            count += 1

    log_action("watched_program", "hackerone", None,
               {"handle": handle, "scopes": count}, db_path)

    return {
        "handle": handle,
        "name": program["name"],
        "scopes_snapshotted": count,
        "project_id": project_id,
    }


def unwatch_program(handle: str, db_path=None):
    """Remove a program from the watchlist and delete its snapshots."""
    from ..core.database import get_connection
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM h1_watched_programs WHERE handle = ?", (handle,))
        conn.execute("DELETE FROM h1_scope_snapshots WHERE handle = ?", (handle,))
    log_action("unwatched_program", "hackerone", None, {"handle": handle}, db_path)


def list_watched(db_path=None) -> list[dict]:
    """List all watched programs."""
    from ..core.database import get_connection
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """SELECT w.handle, w.name, w.project_id, w.last_checked_at,
                      w.last_changed_at, w.created_at,
                      (SELECT COUNT(*) FROM h1_scope_snapshots s
                       WHERE s.handle = w.handle) as scope_count
               FROM h1_watched_programs w
               ORDER BY w.handle"""
        ).fetchall()
    return [dict(r) for r in rows]


def check_program(handle: str, auto_import: bool = False, db_path=None) -> dict:
    """
    Check a single watched program for scope changes.

    Returns {
        handle, name, new: [...], removed: [...], changed: [...],
        has_changes: bool, auto_imported: int
    }
    """
    from ..core.database import get_connection

    program = get_program(handle)
    current_scopes = {}
    for s in program.get("scopes", []):
        key = (s["asset_identifier"], s["asset_type"])
        current_scopes[key] = {
            "asset_identifier": s["asset_identifier"],
            "asset_type": s["asset_type"],
            "eligible_for_bounty": bool(s.get("eligible_for_bounty")),
            "eligible_for_submission": bool(s.get("eligible_for_submission", True)),
            "max_severity": s.get("max_severity", ""),
            "instruction": s.get("instruction", ""),
        }

    # Load previous snapshot
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM h1_scope_snapshots WHERE handle = ?", (handle,)
        ).fetchall()

    previous = {}
    for r in rows:
        key = (r["asset_identifier"], r["asset_type"])
        previous[key] = {
            "asset_identifier": r["asset_identifier"],
            "asset_type": r["asset_type"],
            "eligible_for_bounty": bool(r["eligible_for_bounty"]),
            "eligible_for_submission": bool(r["eligible_for_submission"]),
            "max_severity": r["max_severity"] or "",
            "instruction": r["instruction"] or "",
        }

    # Diff
    new = []
    removed = []
    changed = []

    for key, scope in current_scopes.items():
        if key not in previous:
            new.append(scope)
        else:
            old = previous[key]
            diffs = {}
            for field in ("eligible_for_bounty", "eligible_for_submission", "max_severity"):
                if scope[field] != old[field]:
                    diffs[field] = {"old": old[field], "new": scope[field]}
            if diffs:
                changed.append({**scope, "changes": diffs})

    for key in previous:
        if key not in current_scopes:
            removed.append(previous[key])

    has_changes = bool(new or removed or changed)

    # Update snapshot
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM h1_scope_snapshots WHERE handle = ?", (handle,))
        for key, scope in current_scopes.items():
            conn.execute(
                """INSERT INTO h1_scope_snapshots
                   (handle, asset_identifier, asset_type, eligible_for_bounty,
                    eligible_for_submission, max_severity, instruction)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (handle, scope["asset_identifier"], scope["asset_type"],
                 1 if scope["eligible_for_bounty"] else 0,
                 1 if scope["eligible_for_submission"] else 0,
                 scope["max_severity"], scope["instruction"]),
            )

        # Update watch metadata
        update_fields = "last_checked_at = datetime('now')"
        if has_changes:
            update_fields += ", last_changed_at = datetime('now')"
        conn.execute(
            f"UPDATE h1_watched_programs SET {update_fields} WHERE handle = ?",
            (handle,),
        )

        # Get linked project for auto-import
        row = conn.execute(
            "SELECT project_id FROM h1_watched_programs WHERE handle = ?",
            (handle,),
        ).fetchone()
        project_id = row["project_id"] if row else None

    # Auto-import new scope into linked project
    auto_imported = 0
    if auto_import and project_id and new:
        from .scope import add_rule
        from .targets import add_target
        for s in new:
            asset_type = H1_ASSET_TYPE_MAP.get(s["asset_type"], "other")
            in_scope = s["eligible_for_submission"]
            try:
                add_target(project_id, asset_type, s["asset_identifier"],
                           in_scope=in_scope, db_path=db_path)
                auto_imported += 1
            except Exception:
                pass
            try:
                add_rule(project_id, s["asset_identifier"],
                         rule_type="include" if in_scope else "exclude",
                         source="hackerone", db_path=db_path)
            except Exception:
                pass

    if has_changes:
        log_action("scope_change_detected", "hackerone", project_id,
                   {"handle": handle, "new": len(new), "removed": len(removed),
                    "changed": len(changed), "auto_imported": auto_imported},
                   db_path)

    return {
        "handle": handle,
        "name": program["name"],
        "new": new,
        "removed": removed,
        "changed": changed,
        "has_changes": has_changes,
        "auto_imported": auto_imported,
        "project_id": project_id,
    }


def check_all_watched(auto_import: bool = False, db_path=None) -> list[dict]:
    """Check all watched programs for scope changes."""
    watched = list_watched(db_path)
    results = []
    for w in watched:
        result = check_program(w["handle"], auto_import=auto_import, db_path=db_path)
        results.append(result)
    return results


def check_new_programs(db_path=None) -> list[dict]:
    """
    Find recently launched H1 programs that you're not already watching.
    Returns programs sorted by launch date (newest first).
    """
    from ..core.database import get_connection

    all_progs = list_programs(offers_bounties=True)

    # Get handles we're already watching or have imported
    with get_connection(db_path) as conn:
        watched = {r["handle"] for r in conn.execute(
            "SELECT handle FROM h1_watched_programs"
        ).fetchall()}
        imported = {r["h1_handle"] for r in conn.execute(
            "SELECT h1_handle FROM projects WHERE h1_handle IS NOT NULL"
        ).fetchall()}

    known = watched | imported
    new_progs = [p for p in all_progs if p["handle"] not in known]

    # Sort by start date (newest first)
    new_progs.sort(key=lambda p: p.get("started_accepting_at", ""), reverse=True)

    return new_progs
