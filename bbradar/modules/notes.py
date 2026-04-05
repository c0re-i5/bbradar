"""
Notes module.

Timestamped, tagged notes linked to projects, targets, or vulnerabilities.
Supports search and export for documentation.
"""

from ..core.database import get_connection
from ..core.audit import log_action
from ..core.utils import timestamp_now


def create_note(content: str, title: str = None, project_id: int = None,
                target_id: int = None, vuln_id: int = None,
                tags: str = None, db_path=None) -> int:
    """Create a new note. Returns the note ID."""
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO notes (project_id, target_id, vuln_id, title, content, tags)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (project_id, target_id, vuln_id, title, content, tags),
        )
        nid = cursor.lastrowid
    log_action("created", "note", nid,
               {"project_id": project_id, "title": title}, db_path)
    return nid


def list_notes(project_id: int = None, target_id: int = None, vuln_id: int = None,
               tag: str = None, search: str = None,
               limit: int = 100, db_path=None) -> list[dict]:
    """List notes with optional filters and text search."""
    with get_connection(db_path) as conn:
        query = "SELECT * FROM notes WHERE 1=1"
        params: list = []
        if project_id is not None:
            query += " AND project_id = ?"
            params.append(project_id)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        if vuln_id is not None:
            query += " AND vuln_id = ?"
            params.append(vuln_id)
        if tag:
            escaped_tag = tag.replace('%', r'\%').replace('_', r'\_')
            query += " AND ',' || tags || ',' LIKE ? ESCAPE '\\'"
            params.append(f"%,{escaped_tag},%")
        if search:
            escaped_search = search.replace('%', r'\%').replace('_', r'\_')
            query += " AND (content LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\')"
            params.extend([f"%{escaped_search}%", f"%{escaped_search}%"])
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_note(note_id: int, db_path=None) -> dict | None:
    """Get a single note by ID."""
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    return dict(row) if row else None


def update_note(note_id: int, db_path=None, **kwargs) -> bool:
    """Update note fields."""
    allowed = {"title", "content", "tags", "project_id", "target_id", "vuln_id"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return False
    updates["updated_at"] = timestamp_now()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [note_id]
    with get_connection(db_path) as conn:
        conn.execute(f"UPDATE notes SET {set_clause} WHERE id = ?", values)
    log_action("updated", "note", note_id, updates, db_path)
    return True


def delete_note(note_id: int, db_path=None) -> bool:
    """Delete a note."""
    with get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        if cursor.rowcount == 0:
            return False
    log_action("deleted", "note", note_id, db_path=db_path)
    return True


def export_notes(project_id: int = None, output_path: str = None,
                 db_path=None) -> str:
    """Export notes to a Markdown file. Returns file path."""
    from pathlib import Path
    from ..core.config import load_config

    notes = list_notes(project_id=project_id, limit=10000, db_path=db_path)
    if not notes:
        return ""

    lines = ["# Assessment Notes\n"]
    if project_id is not None:
        from .projects import get_project
        proj = get_project(project_id, db_path)
        if proj:
            lines[0] = f"# Notes — {proj['name']}\n"

    for note in notes:
        lines.append(f"## {note.get('title') or 'Untitled'}")
        lines.append(f"*Created: {note['created_at']}*")
        if note.get("tags"):
            lines.append(f"*Tags: {note['tags']}*")
        lines.append("")
        lines.append(note["content"])
        lines.append("\n---\n")

    if not output_path:
        cfg = load_config()
        output_path = str(Path(cfg["exports_dir"]) / f"notes_export.md")
    Path(output_path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    Path(output_path).write_text("\n".join(lines))
    log_action("exported", "note", None,
               {"count": len(notes), "file": output_path}, db_path)
    return output_path
