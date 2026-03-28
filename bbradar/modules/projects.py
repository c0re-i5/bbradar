"""
Project management module.

Handles CRUD for bug bounty programs / assessment engagements.
"""

from ..core.database import get_connection
from ..core.audit import log_action
from ..core.utils import timestamp_now


def create_project(name: str, platform: str = None, program_url: str = None,
                   scope_raw: str = None, rules: str = None, db_path=None) -> int:
    """Create a new project. Returns the project ID."""
    if not name or not name.strip():
        raise ValueError("Project name cannot be empty")
    name = name.strip()
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO projects (name, platform, program_url, scope_raw, rules)
               VALUES (?, ?, ?, ?, ?)""",
            (name, platform, program_url, scope_raw, rules),
        )
        pid = cursor.lastrowid
    log_action("created", "project", pid, {"name": name, "platform": platform}, db_path)
    return pid


def list_projects(status: str = None, db_path=None) -> list[dict]:
    """List projects, optionally filtered by status."""
    with get_connection(db_path) as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM projects WHERE status = ? ORDER BY updated_at DESC", (status,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM projects ORDER BY updated_at DESC"
            ).fetchall()
    return [dict(r) for r in rows]


def get_project(project_id: int = None, name: str = None, db_path=None) -> dict | None:
    """Get a single project by ID or name."""
    with get_connection(db_path) as conn:
        if project_id:
            row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        elif name:
            row = conn.execute("SELECT * FROM projects WHERE name = ?", (name,)).fetchone()
        else:
            return None
    return dict(row) if row else None


def update_project(project_id: int, db_path=None, **kwargs) -> bool:
    """Update project fields. Pass field=value as keyword args."""
    allowed = {"name", "platform", "program_url", "scope_raw", "rules", "status"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return False
    updates["updated_at"] = timestamp_now()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [project_id]
    with get_connection(db_path) as conn:
        conn.execute(f"UPDATE projects SET {set_clause} WHERE id = ?", values)
    log_action("updated", "project", project_id, updates, db_path)
    return True


def delete_project(project_id: int, db_path=None) -> bool:
    """Delete a project and all related data (cascades)."""
    with get_connection(db_path) as conn:
        # Unwatch any linked H1 program
        conn.execute(
            "DELETE FROM h1_watched_programs WHERE project_id = ?",
            (project_id,),
        )
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    log_action("deleted", "project", project_id, db_path=db_path)
    return True


def get_project_stats(project_id: int, db_path=None) -> dict:
    """Get summary statistics for a project."""
    with get_connection(db_path) as conn:
        targets = conn.execute(
            "SELECT COUNT(*) as cnt FROM targets WHERE project_id = ?", (project_id,)
        ).fetchone()["cnt"]
        vulns = conn.execute(
            "SELECT COUNT(*) as cnt FROM vulns WHERE project_id = ?", (project_id,)
        ).fetchone()["cnt"]
        vuln_by_severity = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM vulns WHERE project_id = ? GROUP BY severity",
            (project_id,),
        ):
            vuln_by_severity[row["severity"]] = row["cnt"]
        notes = conn.execute(
            "SELECT COUNT(*) as cnt FROM notes WHERE project_id = ?", (project_id,)
        ).fetchone()["cnt"]
        recon = conn.execute(
            """SELECT COUNT(*) as cnt FROM recon_data rd
               JOIN targets t ON rd.target_id = t.id
               WHERE t.project_id = ?""",
            (project_id,),
        ).fetchone()["cnt"]
    return {
        "targets": targets,
        "vulns_total": vulns,
        "vulns_by_severity": vuln_by_severity,
        "notes": notes,
        "recon_data_points": recon,
    }
