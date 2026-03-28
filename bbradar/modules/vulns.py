"""
Vulnerability tracker module.

Full lifecycle tracking of security findings from discovery through
submission and resolution.
"""

import json
from pathlib import Path

from ..core.database import get_connection
from ..core.audit import log_action
from ..core.utils import timestamp_now, validate_cvss_vector, normalize_cwe

VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
VALID_STATUSES = {"new", "confirmed", "reported", "accepted", "duplicate", "resolved", "wontfix"}

# Status transition state machine: maps current_status → allowed next statuses
STATUS_TRANSITIONS = {
    "new":       {"confirmed", "duplicate", "wontfix", "reported"},
    "confirmed": {"reported", "duplicate", "wontfix"},
    "reported":  {"accepted", "duplicate", "wontfix", "resolved"},
    "accepted":  {"resolved"},
    "duplicate": {"new"},          # reopen if wrongly marked duplicate
    "resolved":  {"new"},          # reopen if regression
    "wontfix":   {"new"},          # reopen if reconsidered
}

VALID_VULN_TYPES = {
    "xss", "sqli", "ssrf", "idor", "rce", "lfi", "rfi", "xxe",
    "csrf", "open_redirect", "info_disclosure", "auth_bypass",
    "broken_access_control", "business_logic", "race_condition",
    "subdomain_takeover", "cors", "crlf", "hhi", "ssti",
    "deserialization", "path_traversal", "command_injection",
    "prototype_pollution", "other",
}


def create_vuln(project_id: int, title: str, severity: str = "medium",
                vuln_type: str = None, target_id: int = None,
                description: str = None, impact: str = None,
                reproduction: str = None, evidence: list[str] = None,
                request: str = None, response: str = None,
                remediation: str = None, cvss_score: float = None,
                cvss_vector: str = None, db_path=None) -> int:
    """Create a new vulnerability finding. Returns the vuln ID."""
    severity = severity.lower()
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity '{severity}'. Valid: {VALID_SEVERITIES}")
    if vuln_type and vuln_type not in VALID_VULN_TYPES:
        raise ValueError(f"Invalid vuln_type '{vuln_type}'. Valid: {VALID_VULN_TYPES}")

    # Validate CVSS vector if provided
    if cvss_vector:
        cvss_error = validate_cvss_vector(cvss_vector)
        if cvss_error:
            import sys
            print(f"  ⚠ Warning: {cvss_error}", file=sys.stderr)

    evidence_json = json.dumps(evidence) if evidence else None

    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO vulns (project_id, target_id, title, vuln_type, severity,
               cvss_score, cvss_vector, description, impact, reproduction,
               evidence, request, response, remediation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (project_id, target_id, title, vuln_type, severity,
             cvss_score, cvss_vector, description, impact, reproduction,
             evidence_json, request, response, remediation),
        )
        vid = cursor.lastrowid
    log_action("created", "vuln", vid,
               {"project_id": project_id, "title": title, "severity": severity}, db_path)
    return vid


def list_vulns(project_id: int = None, severity: str = None, status: str = None,
               vuln_type: str = None, target_id: int = None,
               limit: int = 100, db_path=None) -> list[dict]:
    """List vulnerabilities with optional filters."""
    with get_connection(db_path) as conn:
        query = "SELECT * FROM vulns WHERE 1=1"
        params: list = []
        if project_id:
            query += " AND project_id = ?"
            params.append(project_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if vuln_type:
            query += " AND vuln_type = ?"
            params.append(vuln_type)
        if target_id:
            query += " AND target_id = ?"
            params.append(target_id)
        query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, updated_at DESC"
        query += " LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_vuln(vuln_id: int, db_path=None) -> dict | None:
    """Get a single vulnerability by ID."""
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM vulns WHERE id = ?", (vuln_id,)).fetchone()
    return dict(row) if row else None


def update_vuln(vuln_id: int, db_path=None, **kwargs) -> bool:
    """Update vuln fields. Pass field=value as keyword args."""
    allowed = {
        "title", "vuln_type", "severity", "cvss_score", "cvss_vector",
        "description", "impact", "reproduction", "evidence",
        "request", "response", "remediation", "status",
        "bounty_amount", "report_url", "target_id",
    }
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return False

    # Enforce status transition state machine
    if "status" in updates:
        new_status = updates["status"].lower()
        if new_status not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{new_status}'. Valid: {VALID_STATUSES}")
        current = get_vuln(vuln_id, db_path)
        if current:
            current_status = current["status"]
            allowed_next = STATUS_TRANSITIONS.get(current_status, set())
            if new_status != current_status and new_status not in allowed_next:
                raise ValueError(
                    f"Cannot transition from '{current_status}' to '{new_status}'. "
                    f"Allowed: {sorted(allowed_next)}"
                )
        updates["status"] = new_status

    if "severity" in updates:
        updates["severity"] = updates["severity"].lower()
    if "evidence" in updates and isinstance(updates["evidence"], list):
        updates["evidence"] = json.dumps(updates["evidence"])
    updates["updated_at"] = timestamp_now()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [vuln_id]
    with get_connection(db_path) as conn:
        conn.execute(f"UPDATE vulns SET {set_clause} WHERE id = ?", values)
    log_action("updated", "vuln", vuln_id, updates, db_path)
    return True


def delete_vuln(vuln_id: int, db_path=None) -> bool:
    """Delete a vulnerability."""
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM vulns WHERE id = ?", (vuln_id,))
    log_action("deleted", "vuln", vuln_id, db_path=db_path)
    return True


def add_evidence(vuln_id: int, file_path: str, db_path=None) -> bool:
    """Add an evidence file path to a vulnerability."""
    from pathlib import Path as _Path
    fp = _Path(file_path)

    # Validate file exists and size limit
    if fp.exists():
        max_size = 50 * 1024 * 1024  # 50 MB
        if fp.stat().st_size > max_size:
            raise ValueError(
                f"Evidence file too large ({fp.stat().st_size / 1024 / 1024:.1f} MB). "
                f"Maximum: {max_size / 1024 / 1024:.0f} MB"
            )

    vuln = get_vuln(vuln_id, db_path)
    if not vuln:
        return False
    evidence = json.loads(vuln["evidence"]) if vuln["evidence"] else []
    if file_path not in evidence:
        evidence.append(file_path)
        return update_vuln(vuln_id, evidence=evidence, db_path=db_path)
    return False


def get_vuln_stats(project_id: int = None, db_path=None) -> dict:
    """Get vulnerability statistics."""
    with get_connection(db_path) as conn:
        base = "SELECT {} FROM vulns"
        where = " WHERE project_id = ?" if project_id else ""
        params = [project_id] if project_id else []

        total = conn.execute(
            f"SELECT COUNT(*) as cnt FROM vulns{where}", params
        ).fetchone()["cnt"]

        by_severity = {}
        for row in conn.execute(
            f"SELECT severity, COUNT(*) as cnt FROM vulns{where} GROUP BY severity", params
        ):
            by_severity[row["severity"]] = row["cnt"]

        by_status = {}
        for row in conn.execute(
            f"SELECT status, COUNT(*) as cnt FROM vulns{where} GROUP BY status", params
        ):
            by_status[row["status"]] = row["cnt"]

        by_type = {}
        for row in conn.execute(
            f"SELECT vuln_type, COUNT(*) as cnt FROM vulns{where} GROUP BY vuln_type", params
        ):
            by_type[row["vuln_type"] or "unclassified"] = row["cnt"]

        total_bounty = conn.execute(
            f"SELECT COALESCE(SUM(bounty_amount), 0) as total FROM vulns{where}", params
        ).fetchone()["total"]

    return {
        "total": total,
        "by_severity": by_severity,
        "by_status": by_status,
        "by_type": by_type,
        "total_bounty": total_bounty,
    }


def get_allowed_transitions(vuln_id: int, db_path=None) -> list[str]:
    """Return the valid next statuses for a vulnerability."""
    v = get_vuln(vuln_id, db_path)
    if not v:
        return []
    return sorted(STATUS_TRANSITIONS.get(v["status"], set()))


def find_duplicates(vuln_id: int, db_path=None) -> list[dict]:
    """Find potential duplicate vulns across all projects (by title similarity and type)."""
    v = get_vuln(vuln_id, db_path)
    if not v:
        return []

    with get_connection(db_path) as conn:
        # Match by exact title (case-insensitive) or same type + similar CVSS
        rows = conn.execute(
            """SELECT * FROM vulns
               WHERE id != ? AND (
                   LOWER(title) = LOWER(?) OR
                   (vuln_type = ? AND vuln_type IS NOT NULL AND ABS(COALESCE(cvss_score,0) - COALESCE(?,0)) < 0.5)
               )
               ORDER BY project_id, created_at DESC
               LIMIT 50""",
            (vuln_id, v["title"], v.get("vuln_type"), v.get("cvss_score", 0)),
        ).fetchall()
    return [dict(r) for r in rows]


def merge_vulns(source_id: int, target_id: int, db_path=None) -> bool:
    """Merge source vuln into target: combines evidence, notes, and marks source as duplicate."""
    source = get_vuln(source_id, db_path)
    target_v = get_vuln(target_id, db_path)
    if not source or not target_v:
        return False

    # Merge evidence lists
    src_ev = json.loads(source["evidence"]) if source.get("evidence") else []
    tgt_ev = json.loads(target_v["evidence"]) if target_v.get("evidence") else []
    merged_ev = list(dict.fromkeys(tgt_ev + src_ev))  # dedup preserving order

    # Merge descriptions
    merged_desc = target_v.get("description") or ""
    if source.get("description"):
        src_desc = source["description"]
        if src_desc not in merged_desc:
            merged_desc += f"\n\n--- Merged from vuln #{source_id} ---\n{src_desc}"

    # Use the higher CVSS / more severe rating
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    best_sev = target_v["severity"]
    if sev_order.get(source["severity"], 4) < sev_order.get(target_v["severity"], 4):
        best_sev = source["severity"]

    best_cvss = max(
        source.get("cvss_score") or 0,
        target_v.get("cvss_score") or 0,
    ) or None

    with get_connection(db_path) as conn:
        # Update target vuln
        conn.execute(
            """UPDATE vulns SET evidence = ?, description = ?, severity = ?,
               cvss_score = ?, updated_at = ? WHERE id = ?""",
            (json.dumps(merged_ev) if merged_ev else None, merged_desc,
             best_sev, best_cvss, timestamp_now(), target_id),
        )
        # Mark source as duplicate
        conn.execute(
            "UPDATE vulns SET status = 'duplicate', updated_at = ? WHERE id = ?",
            (timestamp_now(), source_id),
        )
        # Re-link notes from source to target
        conn.execute(
            "UPDATE notes SET vuln_id = ? WHERE vuln_id = ?",
            (target_id, source_id),
        )

    log_action("merged", "vuln", target_id,
               {"source_id": source_id, "merged_evidence": len(src_ev)}, db_path)
    return True
