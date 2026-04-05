"""
Target management module.

Handles assets (domains, IPs, URLs, APIs, etc.) associated with projects.
"""

import sys

from ..core.database import get_connection
from ..core.audit import log_action
from ..core.utils import timestamp_now, validate_target_value

VALID_ASSET_TYPES = {"domain", "ip", "url", "mobile_app", "api", "wildcard", "cidr", "other"}
VALID_TIERS = {"critical", "high", "medium", "low"}


def _normalize_value(value: str, asset_type: str) -> str:
    """Normalize a target value: strip whitespace, lowercase domains/URLs."""
    value = value.strip()
    if asset_type in ("domain", "url", "wildcard", "api"):
        value = value.lower()
    return value


def add_target(project_id: int, asset_type: str, value: str,
               in_scope: bool = True, tier: str = None, notes: str = None,
               db_path=None) -> int:
    """Add a target to a project. Returns the target ID."""
    if asset_type not in VALID_ASSET_TYPES:
        raise ValueError(f"Invalid asset_type '{asset_type}'. Must be one of: {VALID_ASSET_TYPES}")
    if tier and tier not in VALID_TIERS:
        raise ValueError(f"Invalid tier '{tier}'. Must be one of: {VALID_TIERS}")
    value = _normalize_value(value, asset_type)
    # Validate target value format
    validation_error = validate_target_value(value, asset_type)
    if validation_error:
        print(f"  ⚠ Warning: {validation_error}", file=sys.stderr)
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO targets (project_id, asset_type, value, in_scope, tier, notes)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (project_id, asset_type, value.strip(), 1 if in_scope else 0, tier, notes),
        )
        tid = cursor.lastrowid
    log_action("created", "target", tid,
               {"project_id": project_id, "asset_type": asset_type, "value": value}, db_path)
    return tid


def bulk_add_targets(project_id: int, asset_type: str, values: list[str],
                     in_scope: bool = True, db_path=None) -> int:
    """Add multiple targets at once. Returns count of inserted targets."""
    added = 0
    skipped = 0
    errors = []
    with get_connection(db_path) as conn:
        for val in values:
            val = _normalize_value(val, asset_type)
            if not val:
                continue
            try:
                result = conn.execute(
                    """INSERT OR IGNORE INTO targets (project_id, asset_type, value, in_scope)
                       VALUES (?, ?, ?, ?)""",
                    (project_id, asset_type, val, 1 if in_scope else 0),
                )
                if result.rowcount > 0:
                    added += 1
                else:
                    skipped += 1
            except Exception as e:
                errors.append(f"{val}: {e}")
    log_action("bulk_created", "target", None,
               {"project_id": project_id, "asset_type": asset_type,
                "added": added, "skipped": skipped, "errors": len(errors)}, db_path)
    if errors:
        print(f"  ⚠ {len(errors)} target(s) failed:", file=sys.stderr)
        for err in errors[:10]:
            print(f"    {err}", file=sys.stderr)
    if skipped:
        print(f"  ℹ {skipped} duplicate(s) skipped", file=sys.stderr)
    return added


def list_targets(project_id: int, asset_type: str = None, in_scope: bool = None,
                 db_path=None) -> list[dict]:
    """List targets for a project with optional filters."""
    with get_connection(db_path) as conn:
        query = "SELECT * FROM targets WHERE project_id = ?"
        params: list = [project_id]
        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type)
        if in_scope is not None:
            query += " AND in_scope = ?"
            params.append(1 if in_scope else 0)
        query += " ORDER BY tier, asset_type, value"
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_target(target_id: int, db_path=None) -> dict | None:
    """Get a single target by ID."""
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    return dict(row) if row else None


def update_target(target_id: int, db_path=None, **kwargs) -> bool:
    """Update target fields."""
    allowed = {"asset_type", "value", "in_scope", "tier", "notes"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return False
    if "in_scope" in updates:
        updates["in_scope"] = 1 if updates["in_scope"] else 0
    updates["updated_at"] = timestamp_now()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [target_id]
    with get_connection(db_path) as conn:
        conn.execute(f"UPDATE targets SET {set_clause} WHERE id = ?", values)
    log_action("updated", "target", target_id, updates, db_path)
    return True


def delete_target(target_id: int, db_path=None) -> bool:
    """Delete a target and its recon data (cascades)."""
    with get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        if cursor.rowcount == 0:
            return False
    log_action("deleted", "target", target_id, db_path=db_path)
    return True


def import_targets_from_file(project_id: int, file_path: str, asset_type: str = "domain",
                             in_scope: bool = True, db_path=None) -> int:
    """Import targets from a text file (one per line). Returns count imported."""
    from pathlib import Path
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    values = [line.strip() for line in p.read_text().splitlines() if line.strip() and not line.startswith("#")]
    return bulk_add_targets(project_id, asset_type, values, in_scope, db_path)
