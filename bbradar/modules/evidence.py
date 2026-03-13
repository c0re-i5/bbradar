"""
Evidence file management.

Handles evidence file size limits, orphan detection, and cleanup.
"""

import json
import os
from pathlib import Path

from ..core.database import get_connection
from ..core.config import load_config
from ..core.audit import log_action

# 50 MB default per-file limit
MAX_EVIDENCE_FILE_SIZE = 50 * 1024 * 1024


def get_evidence_dir() -> Path:
    """Return the evidence directory path."""
    cfg = load_config()
    return Path(cfg.get("evidence_dir", str(Path.home() / ".bbradar" / "evidence")))


def list_evidence_files() -> list[dict]:
    """List all files in the evidence directory with sizes."""
    ev_dir = get_evidence_dir()
    if not ev_dir.exists():
        return []
    files = []
    for f in ev_dir.rglob("*"):
        if f.is_file():
            files.append({
                "path": str(f),
                "relative": str(f.relative_to(ev_dir)),
                "size": f.stat().st_size,
                "modified": f.stat().st_mtime,
            })
    return files


def get_referenced_evidence(db_path=None) -> set[str]:
    """Return all evidence file paths referenced by vulns in the DB."""
    refs = set()
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, evidence FROM vulns WHERE evidence IS NOT NULL"
        ).fetchall()
    for row in rows:
        try:
            paths = json.loads(row["evidence"])
            if isinstance(paths, list):
                refs.update(paths)
        except (json.JSONDecodeError, TypeError):
            pass
    return refs


def find_orphaned_files(db_path=None) -> list[dict]:
    """Find evidence files that are not referenced by any vuln."""
    ev_dir = get_evidence_dir()
    if not ev_dir.exists():
        return []
    referenced = get_referenced_evidence(db_path)
    orphans = []
    for f in ev_dir.rglob("*"):
        if f.is_file():
            fpath = str(f)
            rel = str(f.relative_to(ev_dir))
            # Check both absolute and relative path
            if fpath not in referenced and rel not in referenced:
                orphans.append({
                    "path": fpath,
                    "relative": rel,
                    "size": f.stat().st_size,
                })
    return orphans


def cleanup_orphans(dry_run: bool = True, db_path=None) -> dict:
    """Remove orphaned evidence files. Returns summary."""
    orphans = find_orphaned_files(db_path)
    total_size = sum(o["size"] for o in orphans)
    removed = 0

    if not dry_run:
        for o in orphans:
            try:
                os.remove(o["path"])
                removed += 1
            except OSError:
                pass
        if removed:
            log_action("cleanup_evidence", "evidence", None,
                       {"removed": removed, "freed_bytes": total_size}, db_path)

    return {
        "orphans_found": len(orphans),
        "removed": removed if not dry_run else 0,
        "total_size": total_size,
        "files": orphans,
        "dry_run": dry_run,
    }


def check_file_size(filepath: str, max_bytes: int = MAX_EVIDENCE_FILE_SIZE) -> bool:
    """Check if a file is within the size limit."""
    return os.path.getsize(filepath) <= max_bytes


def get_evidence_stats(db_path=None) -> dict:
    """Return evidence storage statistics."""
    ev_dir = get_evidence_dir()
    all_files = list_evidence_files()
    referenced = get_referenced_evidence(db_path)
    orphans = find_orphaned_files(db_path)

    total_size = sum(f["size"] for f in all_files)
    orphan_size = sum(o["size"] for o in orphans)

    return {
        "evidence_dir": str(ev_dir),
        "total_files": len(all_files),
        "total_size": total_size,
        "referenced": len(all_files) - len(orphans),
        "orphaned": len(orphans),
        "orphan_size": orphan_size,
    }
