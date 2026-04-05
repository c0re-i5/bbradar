"""
Attack surface diffing module.

Compares recon data between snapshots to detect changes in the attack
surface: new/removed subdomains, ports, technologies, endpoints.

Stores deltas as first-class objects and can trigger notifications on
meaningful changes.
"""

import json
import sys
from datetime import datetime

from ..core.database import get_connection
from ..core.audit import log_action


def snapshot_recon(project_id: int, label: str = None, db_path=None) -> dict:
    """
    Take a point-in-time snapshot of all recon data for a project.

    Returns {snapshot_id, project_id, label, counts}.
    """
    with get_connection(db_path) as conn:
        # Gather current recon data for all targets in this project
        rows = conn.execute(
            """SELECT rd.target_id, rd.data_type, rd.value, rd.source_tool,
                      rd.confidence, t.value AS target_value
               FROM recon_data rd
               JOIN targets t ON rd.target_id = t.id
               WHERE t.project_id = ?
               ORDER BY rd.data_type, rd.value""",
            (project_id,),
        ).fetchall()

        snapshot_data = json.dumps([dict(r) for r in rows])
        label = label or datetime.now().strftime("%Y-%m-%d %H:%M")

        cursor = conn.execute(
            """INSERT INTO recon_snapshots (project_id, label, snapshot_data, entry_count)
               VALUES (?, ?, ?, ?)""",
            (project_id, label, snapshot_data, len(rows)),
        )
        snap_id = cursor.lastrowid

    counts = {}
    for r in rows:
        dt = r["data_type"]
        counts[dt] = counts.get(dt, 0) + 1

    log_action("snapshot_created", "recon_snapshot", snap_id,
               {"project_id": project_id, "entries": len(rows)}, db_path)

    return {
        "snapshot_id": snap_id,
        "project_id": project_id,
        "label": label,
        "total_entries": len(rows),
        "counts": counts,
    }


def list_snapshots(project_id: int, limit: int = 20, db_path=None) -> list[dict]:
    """List recon snapshots for a project."""
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """SELECT id, project_id, label, entry_count, created_at
               FROM recon_snapshots
               WHERE project_id = ?
               ORDER BY created_at DESC LIMIT ?""",
            (project_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_snapshot(snapshot_id: int, db_path=None) -> dict | None:
    """Get a snapshot by ID."""
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM recon_snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
    if not row:
        return None
    result = dict(row)
    result["data"] = json.loads(result.pop("snapshot_data", "[]"))
    return result


def diff_snapshots(snapshot_id_old: int, snapshot_id_new: int,
                   db_path=None) -> dict:
    """
    Compare two snapshots and return the delta.

    Returns {added: [...], removed: [...], summary: {type: {added, removed}}}.
    """
    old = get_snapshot(snapshot_id_old, db_path)
    new = get_snapshot(snapshot_id_new, db_path)
    if not old or not new:
        raise ValueError("Snapshot not found")

    old_set = {(e["data_type"], e["value"]) for e in old["data"]}
    new_set = {(e["data_type"], e["value"]) for e in new["data"]}

    added_keys = new_set - old_set
    removed_keys = old_set - new_set

    new_lookup = {(e["data_type"], e["value"]): e for e in new["data"]}
    old_lookup = {(e["data_type"], e["value"]): e for e in old["data"]}

    added = [new_lookup[k] for k in sorted(added_keys)]
    removed = [old_lookup[k] for k in sorted(removed_keys)]

    # Build summary by data_type
    summary = {}
    for dtype, _ in added_keys:
        summary.setdefault(dtype, {"added": 0, "removed": 0})
        summary[dtype]["added"] += 1
    for dtype, _ in removed_keys:
        summary.setdefault(dtype, {"added": 0, "removed": 0})
        summary[dtype]["removed"] += 1

    return {
        "old_snapshot": {"id": old["id"], "label": old["label"], "created_at": old["created_at"]},
        "new_snapshot": {"id": new["id"], "label": new["label"], "created_at": new["created_at"]},
        "added": added,
        "removed": removed,
        "total_added": len(added),
        "total_removed": len(removed),
        "summary": summary,
    }


def diff_current(project_id: int, db_path=None) -> dict:
    """
    Compare the most recent snapshot against the current live recon data.

    Takes a fresh snapshot first, then diffs against the previous one.
    If no prior snapshot exists, returns an empty diff.
    """
    existing = list_snapshots(project_id, limit=1, db_path=db_path)
    if not existing:
        snap = snapshot_recon(project_id, label="initial", db_path=db_path)
        return {
            "old_snapshot": None,
            "new_snapshot": {"id": snap["snapshot_id"], "label": snap["label"]},
            "added": [],
            "removed": [],
            "total_added": 0,
            "total_removed": 0,
            "summary": {},
            "info": "First snapshot created. Run again after new recon to see diffs.",
        }

    old_id = existing[0]["id"]
    new_snap = snapshot_recon(project_id, db_path=db_path)
    return diff_snapshots(old_id, new_snap["snapshot_id"], db_path=db_path)


def auto_diff_and_notify(project_id: int, db_path=None) -> dict:
    """
    Diff current state against last snapshot and send notifications
    if meaningful changes are detected.
    """
    result = diff_current(project_id, db_path=db_path)

    if result["total_added"] == 0 and result["total_removed"] == 0:
        return result

    # Send notification
    try:
        from .notifier import _send_discord, _get_discord_webhook, _send_desktop, get_status
        status = get_status()
        summary_parts = []
        for dtype, counts in sorted(result.get("summary", {}).items()):
            parts = []
            if counts["added"]:
                parts.append(f"+{counts['added']}")
            if counts["removed"]:
                parts.append(f"-{counts['removed']}")
            summary_parts.append(f"{dtype}: {', '.join(parts)}")

        msg = (
            f"🔄 **Attack Surface Change** — Project #{project_id}\n"
            f"+{result['total_added']} new, -{result['total_removed']} removed\n"
            + "\n".join(summary_parts[:10])
        )

        if status["discord"]["configured"]:
            _send_discord(msg, webhook_url=_get_discord_webhook("scope"))
        if status["desktop"]["enabled"]:
            _send_desktop(
                "BBRadar: Attack Surface Change",
                f"+{result['total_added']} new, -{result['total_removed']} removed",
            )
    except Exception:
        pass

    log_action("diff_completed", "recon_snapshot", None, {
        "project_id": project_id,
        "added": result["total_added"],
        "removed": result["total_removed"],
    }, db_path)

    return result
