"""
Live scanner integration — connect to running Burp Suite or OWASP ZAP instances.

Provides a unified interface for:
  - Checking scanner connectivity (health/status)
  - Pushing BBRadar scope rules into the scanner
  - Launching spiders and active scans against targets
  - Polling for scan completion and auto-ingesting results
  - Importing all current findings from the scanner
  - Continuous monitoring with auto-ingest
"""

import json
import logging
import sys
import time
from urllib.parse import urlparse

from ..core.config import load_config, get_config_value
from ..core.database import get_connection
from ..core.audit import log_action
from ..core.utils import timestamp_now

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
# Configuration helpers
# ═══════════════════════════════════════════════════════════════════

DEFAULT_ZAP_URL = "http://localhost:8080"
DEFAULT_BURP_URL = "http://localhost:1337"

CONFIDENCE_MAP_ZAP = {
    "0": "tentative", "1": "tentative",
    "2": "firm", "3": "certain",
    "false positive": "tentative",
    "low": "tentative", "medium": "firm", "high": "certain",
    "confirmed": "certain",
}

CONFIDENCE_MAP_BURP = {
    "certain": "certain", "firm": "firm", "tentative": "tentative",
}

# Terminal statuses for a persisted scan run. ``running`` is not terminal.
SCAN_STATUSES = (
    "running", "completed", "failed", "stopped", "paused", "timed_out", "cancelled",
)
_TERMINAL_SCAN_STATUSES = set(SCAN_STATUSES) - {"running"}

DEFAULT_SPIDER_TIMEOUT = 1800
DEFAULT_SCAN_TIMEOUT = 3600

_ZAP_STATE_MAP = {
    "FINISHED": "completed",
    "COMPLETE": "completed",
    "COMPLETED": "completed",
    "PAUSED": "paused",
    "STOPPED": "stopped",
    "ABORTED": "stopped",
    "CANCELLED": "cancelled",
    "CANCELED": "cancelled",
    "FAILED": "failed",
    "ERROR": "failed",
}
_ZAP_RUNNING = {"", "RUNNING", "NOT_STARTED", "PENDING", "IN_PROGRESS", "IN PROGRESS"}

_BURP_STATE_MAP = {
    "succeeded": "completed",
    "success": "completed",
    "completed": "completed",
    "finished": "completed",
    "failed": "failed",
    "failure": "failed",
    "error": "failed",
    "paused": "paused",
    "stopped": "stopped",
    "cancelled": "cancelled",
    "canceled": "cancelled",
    "aborted": "cancelled",
}
_BURP_RUNNING = {"", "queued", "running", "crawling", "auditing", "pending", "in_progress"}


def _get_scanner_config(scanner_type: str) -> dict:
    """Get connection settings for a scanner type."""
    cfg = load_config()
    if scanner_type == "zap":
        return {
            "url": get_config_value("scanner.zap.url", cfg) or DEFAULT_ZAP_URL,
            "api_key": get_config_value("scanner.zap.api_key", cfg) or "",
        }
    elif scanner_type == "burp":
        return {
            "url": get_config_value("scanner.burp.url", cfg) or DEFAULT_BURP_URL,
            "api_key": get_config_value("scanner.burp.api_key", cfg) or "",
        }
    raise ValueError(f"Unknown scanner type: {scanner_type}")


def _require_requests():
    """Import and return the requests library."""
    try:
        import requests
        return requests
    except ImportError:
        raise RuntimeError(
            "The 'requests' library is required for scanner integration. "
            "Install it with: pip install requests"
        )


# ═══════════════════════════════════════════════════════════════════
# Status / Health Check
# ═══════════════════════════════════════════════════════════════════

def check_status(scanner_type: str = None) -> list[dict]:
    """
    Check connectivity to configured scanners.
    Returns list of {scanner, url, status, version, error}.
    """
    requests = _require_requests()
    results = []
    types_to_check = [scanner_type] if scanner_type else ["zap", "burp"]

    for stype in types_to_check:
        cfg = _get_scanner_config(stype)
        url = cfg["url"].rstrip("/")
        result = {"scanner": stype, "url": url, "status": "offline", "version": "", "error": ""}

        try:
            if stype == "zap":
                params = {}
                if cfg["api_key"]:
                    params["apikey"] = cfg["api_key"]
                resp = requests.get(f"{url}/JSON/core/view/version/",
                                    params=params, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    result["status"] = "online"
                    result["version"] = data.get("version", "unknown")
                else:
                    result["error"] = f"HTTP {resp.status_code}"

            elif stype == "burp":
                headers = {}
                if cfg["api_key"]:
                    headers["Authorization"] = cfg["api_key"]
                resp = requests.get(f"{url}/v0.1/", headers=headers, timeout=5)
                if resp.status_code == 200:
                    result["status"] = "online"
                    result["version"] = "Burp Suite Professional"
                else:
                    result["error"] = f"HTTP {resp.status_code}"

        except requests.ConnectionError:
            result["error"] = "Connection refused"
        except requests.Timeout:
            result["error"] = "Connection timed out"
        except Exception as e:
            result["error"] = str(e)[:100]

        results.append(result)

    return results


def detect_scanner() -> str | None:
    """Auto-detect which scanner is running. Returns 'zap', 'burp', or None."""
    results = check_status()
    for r in results:
        if r["status"] == "online":
            return r["scanner"]
    return None


# ═══════════════════════════════════════════════════════════════════
# ZAP Integration
# ═══════════════════════════════════════════════════════════════════

class ZAPClient:
    """Thin wrapper around ZAP's REST API."""

    def __init__(self, url: str = None, api_key: str = None):
        self.requests = _require_requests()
        cfg = _get_scanner_config("zap")
        self.base_url = (url or cfg["url"]).rstrip("/")
        self.api_key = api_key or cfg["api_key"]

    def _params(self, extra: dict = None) -> dict:
        params = {}
        if self.api_key:
            params["apikey"] = self.api_key
        if extra:
            params.update(extra)
        return params

    def _get(self, path: str, params: dict = None) -> dict:
        resp = self.requests.get(
            f"{self.base_url}{path}",
            params=self._params(params),
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def version(self) -> str:
        return self._get("/JSON/core/view/version/").get("version", "unknown")

    def urls(self) -> list[str]:
        """Get all URLs in ZAP's site tree."""
        data = self._get("/JSON/core/view/urls/")
        return data.get("urls", [])

    def alerts(self, base_url: str = None, start: int = 0,
               count: int = 5000) -> list[dict]:
        """Get alerts from ZAP."""
        params = {"start": str(start), "count": str(count)}
        if base_url:
            params["baseurl"] = base_url
        data = self._get("/JSON/core/view/alerts/", params)
        return data.get("alerts", [])

    def spider_scan(self, url: str, max_children: int = 0) -> str:
        """Start a spider scan. Returns scan ID."""
        params = {"url": url}
        if max_children:
            params["maxChildren"] = str(max_children)
        data = self._get("/JSON/spider/action/scan/", params)
        return data.get("scan", "")

    def spider_status(self, scan_id: str) -> int:
        """Get spider progress (0-100)."""
        data = self._get("/JSON/spider/view/status/", {"scanId": scan_id})
        return int(data.get("status", "0"))

    def active_scan(self, url: str) -> str:
        """Start an active scan. Returns scan ID."""
        data = self._get("/JSON/ascan/action/scan/", {"url": url})
        return data.get("scan", "")

    def active_scan_status(self, scan_id: str) -> int:
        """Get active scan progress (0-100)."""
        data = self._get("/JSON/ascan/view/status/", {"scanId": scan_id})
        return int(data.get("status", "0"))

    def spider_scan_state(self, scan_id: str) -> str:
        """Spider state such as RUNNING, FINISHED, PAUSED, or STOPPED."""
        return self._record_state("/JSON/spider/view/scans/", scan_id)

    def active_scan_state(self, scan_id: str) -> str:
        """Active-scan state such as RUNNING, FINISHED, PAUSED, or STOPPED."""
        return self._record_state("/JSON/ascan/view/scans/", scan_id)

    def _record_state(self, path: str, scan_id: str) -> str:
        try:
            data = self._get(path)
        except Exception:
            logger.debug("Could not read scanner state from %s", path, exc_info=True)
            return ""
        for scan in data.get("scans") or []:
            if str(scan.get("id")) == str(scan_id):
                return str(scan.get("state") or "")
        return ""

    def new_context(self, name: str) -> str:
        """Create a new context. Returns context ID."""
        data = self._get("/JSON/context/action/newContext/",
                         {"contextName": name})
        return data.get("contextId", "")

    def include_in_context(self, context_name: str, regex: str):
        """Add an include regex to a context."""
        self._get("/JSON/context/action/includeInContext/",
                  {"contextName": context_name, "regex": regex})

    def exclude_from_context(self, context_name: str, regex: str):
        """Add an exclude regex to a context."""
        self._get("/JSON/context/action/excludeFromContext/",
                  {"contextName": context_name, "regex": regex})

    def messages(self, base_url: str = None, start: int = 0,
                 count: int = 500) -> list[dict]:
        """Get proxy history messages."""
        params = {"start": str(start), "count": str(count)}
        if base_url:
            params["baseurl"] = base_url
        data = self._get("/JSON/core/view/messages/", params)
        return data.get("messages", [])


class BurpClient:
    """Thin wrapper around Burp Suite Professional's REST API."""

    def __init__(self, url: str = None, api_key: str = None):
        self.requests = _require_requests()
        cfg = _get_scanner_config("burp")
        self.base_url = (url or cfg["url"]).rstrip("/")
        self.api_key = api_key or cfg["api_key"]

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = self.api_key
        return headers

    def _get(self, path: str) -> dict:
        resp = self.requests.get(
            f"{self.base_url}{path}",
            headers=self._headers(),
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    def _post(self, path: str, data: dict = None) -> dict:
        resp = self.requests.post(
            f"{self.base_url}{path}",
            headers=self._headers(),
            json=data or {},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    def scan(self, urls: list[str]) -> str:
        """Launch a scan against one or more URLs. Returns task ID."""
        data = {"urls": urls}
        result = self._post("/v0.1/scan", data)
        return str(result.get("task_id", ""))

    def scan_status(self, task_id: str) -> dict:
        """Get scan status. Returns {status, issue_events}."""
        return self._get(f"/v0.1/scan/{task_id}")

    def scan_issues(self, task_id: str) -> list[dict]:
        """Get issues from a completed scan."""
        data = self.scan_status(task_id)
        return data.get("issue_events", [])


# ═══════════════════════════════════════════════════════════════════
# Scope Sync
# ═══════════════════════════════════════════════════════════════════

def scope_sync(project_id: int, scanner_type: str = None, db_path=None) -> dict:
    """
    Push BBRadar scope rules to a connected scanner.
    Returns {scanner, includes_pushed, excludes_pushed}.
    """
    from .scope import list_rules

    scanner_type = scanner_type or detect_scanner()
    if not scanner_type:
        raise RuntimeError("No scanner detected. Start ZAP or Burp first.")

    rules = list_rules(project_id, db_path=db_path)
    if not rules:
        raise ValueError(f"No scope rules defined for project #{project_id}")

    includes = [r for r in rules if r["rule_type"] == "include"]
    excludes = [r for r in rules if r["rule_type"] == "exclude"]

    result = {"scanner": scanner_type, "includes_pushed": 0, "excludes_pushed": 0}

    if scanner_type == "zap":
        zap = ZAPClient()
        ctx_name = f"bbradar-project-{project_id}"
        zap.new_context(ctx_name)

        for rule in includes:
            regex = _scope_pattern_to_regex(rule["pattern"], rule["pattern_type"])
            if regex:
                zap.include_in_context(ctx_name, regex)
                result["includes_pushed"] += 1

        for rule in excludes:
            regex = _scope_pattern_to_regex(rule["pattern"], rule["pattern_type"])
            if regex:
                zap.exclude_from_context(ctx_name, regex)
                result["excludes_pushed"] += 1

    elif scanner_type == "burp":
        # Burp REST API doesn't support scope configuration
        raise RuntimeError(
            "Burp Suite REST API does not support remote scope configuration. "
            "Configure scope manually in Burp's Target tab."
        )

    log_action("scope_sync", "scanner", None,
               {"project_id": project_id, **result}, db_path)
    return result


def _terminal_from_zap(progress: int, state: str) -> tuple[str | None, str]:
    """Return (terminal status, detail) or (None, '') while the scan is still running."""
    if progress >= 100:
        return "completed", ""
    key = (state or "").strip().upper()
    if key in _ZAP_RUNNING:
        return None, ""
    mapped = _ZAP_STATE_MAP.get(key)
    if mapped:
        return mapped, ""
    # Unrecognized and not running: stop instead of polling forever.
    return "failed", f"unrecognized status: {state}"


def _terminal_from_burp(raw: str) -> tuple[str | None, str]:
    """Return (terminal status, detail) or (None, '') while the scan is still running."""
    key = (raw or "").strip().lower()
    if key in _BURP_RUNNING:
        return None, ""
    mapped = _BURP_STATE_MAP.get(key)
    if mapped:
        return mapped, ""
    return "failed", f"unrecognized status: {raw}"


def _poll_until(read_outcome, timeout: int, poll_interval: int) -> tuple[str, str]:
    """
    Poll ``read_outcome() -> (terminal|None, detail)`` until a terminal state or timeout.

    ``timeout`` is seconds. Zero means give up after the first non-terminal read.
    """
    deadline = time.monotonic() + max(0, timeout)
    while True:
        terminal, detail = read_outcome()
        if terminal:
            return terminal, detail
        if time.monotonic() >= deadline:
            return "timed_out", detail or "timed out"
        time.sleep(max(0, poll_interval))


def _start_scan_run(scanner: str, kind: str, project_id: int, target_id: int,
                    external_id: str, db_path=None) -> int | None:
    """Insert a scan_runs row. Returns None if the insert fails (scan still proceeds)."""
    try:
        with get_connection(db_path) as conn:
            cursor = conn.execute(
                """INSERT INTO scan_runs
                   (scanner, kind, project_id, target_id, external_id, status)
                   VALUES (?, ?, ?, ?, ?, 'running')""",
                (scanner, kind, project_id, target_id, external_id or None),
            )
            return cursor.lastrowid
    except Exception as e:
        logger.warning("Could not record scan run: %s", e)
        return None


def _finish_scan_run(run_id: int | None, status: str, findings_count: int = 0,
                     detail: str = "", db_path=None):
    """Move a scan run to a terminal status. Never leaves it ``running``."""
    if not run_id:
        return
    if status not in _TERMINAL_SCAN_STATUSES:
        status = "failed"
    try:
        with get_connection(db_path) as conn:
            conn.execute(
                """UPDATE scan_runs
                   SET status = ?, findings_count = ?, detail = ?,
                       finished_at = datetime('now')
                   WHERE id = ?""",
                (status, findings_count, detail or None, run_id),
            )
    except Exception as e:
        logger.warning("Could not finalize scan run #%s: %s", run_id, e)


def get_scan_run(run_id: int, db_path=None) -> dict | None:
    """Get a persisted scanner run."""
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
    return dict(row) if row else None


def list_scan_runs(project_id: int = None, target_id: int = None,
                   limit: int = 20, db_path=None) -> list[dict]:
    """List persisted scanner runs, newest first."""
    with get_connection(db_path) as conn:
        query = "SELECT * FROM scan_runs WHERE 1=1"
        params: list = []
        if project_id is not None:
            query += " AND project_id = ?"
            params.append(project_id)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def _alert_key(alert: dict) -> tuple:
    """Stable identity for a ZAP alert, shared by import and the monitor."""
    name = alert.get("name", alert.get("alert", ""))
    return (name, alert.get("url", ""), alert.get("param", ""))


def _scope_pattern_to_regex(pattern: str, pattern_type: str) -> str:
    """Convert a BBRadar scope pattern to a regex suitable for ZAP context."""
    import re

    if pattern_type == "regex":
        return pattern
    elif pattern_type == "exact":
        return f".*{re.escape(pattern)}.*"
    elif pattern_type == "wildcard":
        # *.example.com → .*\.example\.com
        escaped = re.escape(pattern).replace(r"\*", ".*")
        return f".*{escaped}.*"
    elif pattern_type == "cidr":
        # CIDR ranges can't be easily expressed as URL regex — skip
        return ""
    return ""


# ═══════════════════════════════════════════════════════════════════
# Spider
# ═══════════════════════════════════════════════════════════════════

def spider(target_id: int, scanner_type: str = None,
           poll_interval: int = 5, timeout: int = DEFAULT_SPIDER_TIMEOUT,
           db_path=None) -> dict:
    """
    Spider a target using the connected scanner.
    Returns {scanner, target, status, urls_found, recon_added, run_id}.

    Polling stops on a terminal scanner state or when ``timeout`` seconds elapse.
    The scan_runs row is always finalized.
    """
    from .targets import get_target
    from .recon import bulk_add_recon
    from .projects import require_active_project

    scanner_type = scanner_type or detect_scanner()
    if not scanner_type:
        raise RuntimeError("No scanner detected. Start ZAP or Burp first.")

    target = get_target(target_id, db_path)
    if not target:
        raise ValueError(f"Target #{target_id} not found")
    require_active_project(target["project_id"], db_path, action="Spidering a target")

    target_url = _target_to_url(target["value"])
    result = {"scanner": scanner_type, "target": target["value"],
              "status": "running", "urls_found": 0, "recon_added": 0,
              "run_id": None, "detail": ""}

    if scanner_type == "burp":
        raise RuntimeError(
            "Burp Suite REST API does not support standalone spidering. "
            "Use 'bb scanner scan' which includes crawling."
        )
    if scanner_type != "zap":
        raise ValueError(f"Unknown scanner type: {scanner_type}")

    zap = ZAPClient()
    scan_id = zap.spider_scan(target_url)
    run_id = _start_scan_run(
        "zap", "spider", target["project_id"], target_id, scan_id, db_path,
    )
    result["run_id"] = run_id
    final_status = "failed"
    detail = ""
    try:
        def _read():
            progress = zap.spider_status(scan_id)
            print(f"\r  Spider progress: {progress}%", end="", flush=True,
                  file=sys.stderr)
            state = "" if progress >= 100 else zap.spider_scan_state(scan_id)
            terminal, why = _terminal_from_zap(progress, state)
            if terminal is None:
                why = f"progress {progress}%"
            return terminal, why

        final_status, detail = _poll_until(_read, timeout, poll_interval)
        print(file=sys.stderr)
        result["status"] = final_status
        result["detail"] = detail
        if final_status == "completed":
            urls = zap.urls()
            target_host = urlparse(target_url).hostname or target["value"]
            relevant = [u for u in urls if target_host in u]
            result["urls_found"] = len(relevant)
            if relevant:
                added = bulk_add_recon(target_id, "url", relevant,
                                       source_tool="zap-spider", db_path=db_path)
                result["recon_added"] = added
    except KeyboardInterrupt:
        final_status = "cancelled"
        result["status"] = "cancelled"
        raise
    except Exception:
        final_status = "failed"
        result["status"] = "failed"
        raise
    finally:
        _finish_scan_run(run_id, final_status, result["urls_found"], detail, db_path)

    log_action("spider", "scanner", target_id,
               {"scanner": scanner_type, "status": result["status"],
                "urls_found": result["urls_found"]}, db_path)
    return result


# ═══════════════════════════════════════════════════════════════════
# Active Scan
# ═══════════════════════════════════════════════════════════════════

def scan(target_id: int, project_id: int, scanner_type: str = None,
         auto_import: bool = True, poll_interval: int = 10,
         timeout: int = DEFAULT_SCAN_TIMEOUT, db_path=None) -> dict:
    """
    Launch an active scan against a target using the connected scanner.
    Polls until a terminal state or ``timeout`` seconds, then optionally
    imports findings from a completed or failed scan.

    Returns {scanner, target, status, findings_count, imported_ids, run_id, detail}.
    A stopped, paused, or timed-out scan is not reported as completed.
    """
    from .targets import get_target
    from .projects import require_active_project

    scanner_type = scanner_type or detect_scanner()
    if not scanner_type:
        raise RuntimeError("No scanner detected. Start ZAP or Burp first.")

    target = get_target(target_id, db_path)
    if not target:
        raise ValueError(f"Target #{target_id} not found")
    require_active_project(project_id, db_path, action="Running a scan")

    target_url = _target_to_url(target["value"])
    result = {"scanner": scanner_type, "target": target["value"],
              "status": "running", "findings_count": 0, "imported_ids": [],
              "run_id": None, "detail": ""}

    if scanner_type == "zap":
        client_kind = "zap"
        zap = ZAPClient()
        external_id = zap.active_scan(target_url)

        def _read():
            progress = zap.active_scan_status(external_id)
            print(f"\r  Active scan progress: {progress}%", end="",
                  flush=True, file=sys.stderr)
            state = "" if progress >= 100 else zap.active_scan_state(external_id)
            terminal, why = _terminal_from_zap(progress, state)
            if terminal is None:
                why = f"progress {progress}%"
            return terminal, why

        def _collect():
            alerts = zap.alerts(base_url=target_url)
            result["findings_count"] = len(alerts)
            if auto_import and alerts:
                ids = _import_zap_alerts(alerts, project_id, target_id, db_path)
                result["imported_ids"] = ids

    elif scanner_type == "burp":
        client_kind = "burp"
        burp = BurpClient()
        external_id = burp.scan([target_url])

        def _read():
            status = burp.scan_status(external_id)
            raw = status.get("scan_status", "")
            print(f"\r  Burp scan status: {raw or 'unknown'}", end="",
                  flush=True, file=sys.stderr)
            terminal, why = _terminal_from_burp(raw)
            if terminal is None:
                why = f"last status: {raw or 'unknown'}"
            return terminal, why

        def _collect():
            issues = burp.scan_issues(external_id)
            result["findings_count"] = len(issues)
            if auto_import and issues:
                ids = _import_burp_issues(issues, project_id, target_id, db_path)
                result["imported_ids"] = ids

    else:
        raise ValueError(f"Unknown scanner type: {scanner_type}")

    run_id = _start_scan_run(
        client_kind, "active", project_id, target_id, external_id, db_path,
    )
    result["run_id"] = run_id
    final_status = "failed"
    detail = ""
    try:
        final_status, detail = _poll_until(_read, timeout, poll_interval)
        print(file=sys.stderr)
        result["status"] = final_status
        result["detail"] = detail
        # Partial runs (paused, stopped, timed out, cancelled) are not imported.
        if final_status in ("completed", "failed"):
            _collect()
    except KeyboardInterrupt:
        final_status = "cancelled"
        result["status"] = "cancelled"
        raise
    except Exception:
        final_status = "failed"
        result["status"] = "failed"
        raise
    finally:
        _finish_scan_run(
            run_id, final_status, result["findings_count"], detail, db_path,
        )

    log_action("scan", "scanner", target_id,
               {"scanner": scanner_type, "status": result["status"],
                "findings": result["findings_count"]}, db_path)
    return result


# ═══════════════════════════════════════════════════════════════════
# Import Findings from Scanner
# ═══════════════════════════════════════════════════════════════════

def import_findings(project_id: int, scanner_type: str = None,
                    target_id: int = None, base_url: str = None,
                    db_path=None) -> dict:
    """
    Import all current findings from a connected scanner.
    Returns {scanner, total, imported, duplicates, imported_ids}.
    """
    scanner_type = scanner_type or detect_scanner()
    if not scanner_type:
        raise RuntimeError("No scanner detected. Start ZAP or Burp first.")

    result = {"scanner": scanner_type, "total": 0, "imported": 0,
              "duplicates": 0, "imported_ids": []}

    if scanner_type == "zap":
        zap = ZAPClient()
        alerts = zap.alerts(base_url=base_url)
        result["total"] = len(alerts)
        if alerts:
            ids = _import_zap_alerts(alerts, project_id, target_id, db_path)
            result["imported"] = len(ids)
            result["duplicates"] = len(alerts) - len(ids)
            result["imported_ids"] = ids

    elif scanner_type == "burp":
        burp = BurpClient()
        # Burp REST API doesn't have a "get all issues" endpoint without a scan task
        raise RuntimeError(
            "Burp Suite REST API only returns issues per-scan. "
            "Use 'bb scanner scan' to launch a scan and auto-import results, "
            "or 'bb ingest' with an exported XML file."
        )

    log_action("import", "scanner", None,
               {"project_id": project_id, **result}, db_path)
    return result


# ═══════════════════════════════════════════════════════════════════
# Import Helpers
# ═══════════════════════════════════════════════════════════════════

# ZAP alert name → vuln_type mapping (supplement to parser)
_ZAP_TYPE_MAP = {
    "cross site scripting": "xss",
    "sql injection": "sqli",
    "path traversal": "path_traversal",
    "remote file inclusion": "rfi",
    "command injection": "command_injection",
    "remote code execution": "rce",
    "server side request forgery": "ssrf",
    "cross-site request forgery": "csrf",
    "open redirect": "open_redirect",
    "external redirect": "open_redirect",
    "information disclosure": "info_disclosure",
    "directory browsing": "info_disclosure",
    "clickjacking": "other",
    "x-frame-options": "other",
    "content security policy": "other",
    "strict-transport-security": "other",
    "cookie": "other",
    "session fixation": "other",
    "xml external entity": "xxe",
    "ldap injection": "other",
    "server side template injection": "ssti",
    "deserialization": "deserialization",
}

_BURP_TYPE_MAP = {
    "cross-site scripting": "xss",
    "reflected cross-site scripting": "xss",
    "stored cross-site scripting": "xss",
    "dom-based cross-site scripting": "xss",
    "sql injection": "sqli",
    "blind sql injection": "sqli",
    "os command injection": "command_injection",
    "server-side template injection": "ssti",
    "server-side request forgery": "ssrf",
    "file path traversal": "path_traversal",
    "remote file inclusion": "rfi",
    "local file inclusion": "lfi",
    "broken access control": "broken_access_control",
    "cross-site request forgery": "csrf",
    "xml external entity injection": "xxe",
    "open redirection": "open_redirect",
}

_ZAP_RISK_MAP = {"0": "informational", "1": "low", "2": "medium", "3": "high"}


def _classify_zap_alert(name: str) -> str:
    """Map a ZAP alert name to a BBRadar vuln_type."""
    name_lower = name.lower()
    for key, vtype in _ZAP_TYPE_MAP.items():
        if key in name_lower:
            return vtype
    return "other"


def _classify_burp_issue(name: str) -> str:
    """Map a Burp issue name to a BBRadar vuln_type."""
    name_lower = name.lower()
    for key, vtype in _BURP_TYPE_MAP.items():
        if key in name_lower:
            return vtype
    return "other"


def _import_zap_alerts(alerts: list[dict], project_id: int,
                       target_id: int = None, db_path=None,
                       _failed: list | None = None) -> list[int]:
    """Convert ZAP alerts to vulns, dedup, and create. Returns created vuln IDs.

    Alert identities that failed to import are appended to ``_failed`` so the
    monitor can retry them instead of treating them as seen.
    """
    from .vulns import create_vuln, list_vulns, VALID_VULN_TYPES

    existing = list_vulns(project_id=project_id, limit=10000, db_path=db_path)
    existing_titles = {(v["title"].lower().strip(), v.get("vuln_type", "")) for v in existing}

    created = []
    seen = set()

    for alert in alerts:
        name = alert.get("name", alert.get("alert", "Unknown Alert"))
        risk = str(alert.get("risk", alert.get("riskcode", "0")))
        confidence = str(alert.get("confidence", "2"))
        url = alert.get("url", "")
        desc = alert.get("description", "")
        solution = alert.get("solution", "")
        cwe_raw = alert.get("cweid", "")
        evidence = alert.get("evidence", "")

        severity = _ZAP_RISK_MAP.get(risk, "informational")
        vuln_type = _classify_zap_alert(name)
        if vuln_type not in VALID_VULN_TYPES:
            vuln_type = "other"

        title = f"{name}"
        if url:
            parsed = urlparse(url)
            path = parsed.path or "/"
            title = f"{name} — {parsed.hostname}{path}"

        # Dedup
        dedup_key = (title.lower().strip(), vuln_type)
        if dedup_key in existing_titles or dedup_key in seen:
            continue
        seen.add(dedup_key)

        cwe_id = f"CWE-{cwe_raw}" if cwe_raw and cwe_raw != "-1" else None
        conf = CONFIDENCE_MAP_ZAP.get(confidence, "firm")

        full_desc = desc
        if url:
            full_desc = f"**URL:** {url}\n\n{desc}"
        if evidence:
            full_desc += f"\n\n**Evidence:**\n```\n{evidence[:2000]}\n```"

        try:
            vid = create_vuln(
                project_id=project_id,
                target_id=target_id,
                title=title[:200],
                severity=severity,
                vuln_type=vuln_type,
                description=full_desc,
                remediation=solution or None,
                source_tool="zap",
                confidence=conf,
                cwe_id=cwe_id,
                db_path=db_path,
            )
            created.append(vid)
        except Exception as e:
            logger.warning("Failed to create vuln from ZAP alert '%s': %s", name, e)
            if _failed is not None:
                _failed.append(_alert_key(alert))

    return created


def _import_burp_issues(issues: list[dict], project_id: int,
                        target_id: int = None, db_path=None) -> list[int]:
    """Convert Burp scan issues to vulns, dedup, and create. Returns created vuln IDs."""
    from .vulns import create_vuln, list_vulns, VALID_VULN_TYPES

    existing = list_vulns(project_id=project_id, limit=10000, db_path=db_path)
    existing_titles = {(v["title"].lower().strip(), v.get("vuln_type", "")) for v in existing}

    created = []
    seen = set()

    for event in issues:
        issue = event.get("issue", event)
        name = issue.get("name", "Unknown Issue")
        severity = (issue.get("severity") or "information").lower()
        confidence = (issue.get("confidence") or "firm").lower()
        origin = issue.get("origin", "")
        path = issue.get("path", "")
        desc = issue.get("issueDetail", issue.get("description", ""))

        # Normalize severity
        if severity == "information":
            severity = "informational"
        if severity not in ("critical", "high", "medium", "low", "informational"):
            severity = "informational"

        vuln_type = _classify_burp_issue(name)
        if vuln_type not in VALID_VULN_TYPES:
            vuln_type = "other"

        title = f"{name}"
        if origin and path:
            title = f"{name} — {origin}{path}"

        dedup_key = (title.lower().strip(), vuln_type)
        if dedup_key in existing_titles or dedup_key in seen:
            continue
        seen.add(dedup_key)

        conf = CONFIDENCE_MAP_BURP.get(confidence, "firm")

        full_desc = ""
        if origin and path:
            full_desc = f"**URL:** {origin}{path}\n\n"
        full_desc += desc or ""

        try:
            vid = create_vuln(
                project_id=project_id,
                target_id=target_id,
                title=title[:200],
                severity=severity,
                vuln_type=vuln_type,
                description=full_desc,
                source_tool="burp",
                confidence=conf,
                db_path=db_path,
            )
            created.append(vid)
        except Exception as e:
            logger.warning("Failed to create vuln from Burp issue '%s': %s", name, e)

    return created


# ═══════════════════════════════════════════════════════════════════
# Monitor (continuous import)
# ═══════════════════════════════════════════════════════════════════

def monitor(project_id: int, scanner_type: str = None,
            interval: int = 30, target_id: int = None,
            db_path=None, max_cycles: int = 0) -> dict:
    """
    Continuously poll a scanner for new findings and auto-import.

    Args:
        project_id: Project to import into
        scanner_type: 'zap' or 'burp' (auto-detect if None)
        interval: Seconds between polls
        target_id: Optional target to associate findings with
        max_cycles: Max poll iterations (0 = unlimited, for testing)

    Returns final stats dict.
    """
    scanner_type = scanner_type or detect_scanner()
    if not scanner_type:
        raise RuntimeError("No scanner detected. Start ZAP or Burp first.")

    if scanner_type != "zap":
        raise RuntimeError("Monitor mode is currently supported for ZAP only.")

    stats = {"total_imported": 0, "cycles": 0, "errors": 0}
    seen_alerts = set()

    cycle = 0
    while True:
        cycle += 1
        stats["cycles"] = cycle

        try:
            zap = ZAPClient()
            alerts = zap.alerts()
        except Exception as e:
            stats["errors"] += 1
            logger.warning("Monitor cycle %d error: %s", cycle, e)
        else:
            pending = []
            for alert in alerts:
                key = _alert_key(alert)
                if key not in seen_alerts:
                    pending.append((key, alert))

            if pending:
                failed: list = []
                try:
                    ids = _import_zap_alerts(
                        [alert for _, alert in pending], project_id,
                        target_id, db_path, _failed=failed,
                    )
                except Exception as e:
                    # Leave every key unseen so the next cycle retries the batch.
                    stats["errors"] += 1
                    logger.warning("Monitor cycle %d import error: %s", cycle, e)
                else:
                    failed_set = set(failed)
                    for key, _alert in pending:
                        if key not in failed_set:
                            seen_alerts.add(key)
                    stats["total_imported"] += len(ids)
                    if ids:
                        print(f"  [{timestamp_now()}] Imported {len(ids)} new findings",
                              file=sys.stderr)

        if max_cycles and cycle >= max_cycles:
            break

        time.sleep(interval)

    return stats


# ═══════════════════════════════════════════════════════════════════
# URL Helpers
# ═══════════════════════════════════════════════════════════════════

def _target_to_url(target_value: str) -> str:
    """Convert a target value (domain, IP, URL) to a URL suitable for scanning."""
    if target_value.startswith("http://") or target_value.startswith("https://"):
        return target_value
    # Default to https
    return f"https://{target_value}"
