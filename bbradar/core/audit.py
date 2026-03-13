"""
Audit logging for BBRadar.

Every significant action (create, update, delete, export, tool run)
is logged to the audit_log table for full traceability.
"""

import json
from .database import get_connection


def log_action(action: str, entity_type: str = None, entity_id: int = None,
               details: dict = None, db_path=None):
    """Record an action in the audit log."""
    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT INTO audit_log (action, entity_type, entity_id, details) VALUES (?, ?, ?, ?)",
            (action, entity_type, entity_id, json.dumps(details) if details else None),
        )


def get_audit_log(entity_type: str = None, entity_id: int = None,
                  limit: int = 50, db_path=None) -> list[dict]:
    """Retrieve audit log entries, optionally filtered."""
    with get_connection(db_path) as conn:
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type)
        if entity_id:
            query += " AND entity_id = ?"
            params.append(entity_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_audit_stats(db_path=None) -> dict:
    """Return audit log statistics."""
    with get_connection(db_path) as conn:
        total = conn.execute("SELECT count(*) FROM audit_log").fetchone()[0]
        oldest = conn.execute(
            "SELECT MIN(timestamp) FROM audit_log"
        ).fetchone()[0]
        by_action = {}
        for row in conn.execute(
            "SELECT action, count(*) as cnt FROM audit_log GROUP BY action ORDER BY cnt DESC"
        ):
            by_action[row["action"]] = row["cnt"]
    return {"total": total, "oldest": oldest, "by_action": by_action}


def purge_audit_log(days: int = 90, db_path=None) -> int:
    """Delete audit log entries older than `days` days. Returns count deleted."""
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM audit_log WHERE timestamp < datetime('now', ?)",
            (f"-{int(days)} days",),
        )
        return cursor.rowcount


def export_audit_log(output_path: str, entity_type: str = None,
                     limit: int = 10000, db_path=None) -> str:
    """Export audit log to a JSON file for archival."""
    from pathlib import Path
    entries = get_audit_log(entity_type=entity_type, limit=limit, db_path=db_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(entries, f, indent=2, default=str)
    return output_path
