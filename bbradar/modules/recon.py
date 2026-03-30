"""
Reconnaissance data module.

Stores, queries, and manages data gathered during recon phases.
Integrates with common Kali tools for automated data ingestion.
"""

import json
import re
import shlex
from pathlib import Path

from ..core.database import get_connection
from ..core.audit import log_action
from ..core.utils import run_tool

# Regex for validating domains/IPs/CIDRs before passing to external tools
_SAFE_TARGET_RE = re.compile(
    r'^[a-zA-Z0-9._:\[\]-]+$'
)

# Allowlist for extra_args characters — rejects shell metacharacters and path traversal
_SAFE_EXTRA_ARGS_RE = re.compile(
    r'^[a-zA-Z0-9 _.,:/@=\-]+$'
)

VALID_DATA_TYPES = {
    "subdomain", "port", "service", "tech", "url", "parameter",
    "dns", "whois", "cert", "screenshot", "header", "email",
    "endpoint", "js_file", "secret", "other",
}


def add_recon(target_id: int, data_type: str, value: str,
              source_tool: str = None, raw_output: str = None,
              confidence: str = "medium", db_path=None) -> int | None:
    """Add a single recon data point. Returns ID or None if duplicate."""
    if data_type not in VALID_DATA_TYPES:
        raise ValueError(f"Invalid data_type '{data_type}'. Valid: {VALID_DATA_TYPES}")
    with get_connection(db_path) as conn:
        try:
            cursor = conn.execute(
                """INSERT INTO recon_data (target_id, data_type, value, source_tool, raw_output, confidence)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (target_id, data_type, value.strip(), source_tool, raw_output, confidence),
            )
            rid = cursor.lastrowid
        except Exception:
            return None  # duplicate
    log_action("created", "recon", rid,
               {"target_id": target_id, "data_type": data_type, "source_tool": source_tool}, db_path)
    return rid


def bulk_add_recon(target_id: int, data_type: str, values: list[str],
                   source_tool: str = None, db_path=None) -> int:
    """Add multiple recon values at once. Returns count of new entries."""
    count = 0
    with get_connection(db_path) as conn:
        for val in values:
            val = val.strip()
            if not val:
                continue
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO recon_data (target_id, data_type, value, source_tool)
                       VALUES (?, ?, ?, ?)""",
                    (target_id, data_type, val, source_tool),
                )
                count += 1
            except Exception as e:
                import sys
                print(f"  warning: skipped recon '{val}': {e}", file=sys.stderr)
    log_action("bulk_created", "recon", None,
               {"target_id": target_id, "data_type": data_type, "count": count, "source_tool": source_tool},
               db_path)
    return count


def list_recon(target_id: int = None, data_type: str = None, source_tool: str = None,
               project_id: int = None, limit: int = 500, db_path=None) -> list[dict]:
    """Query recon data with optional filters."""
    with get_connection(db_path) as conn:
        if project_id:
            query = """SELECT rd.* FROM recon_data rd
                       JOIN targets t ON rd.target_id = t.id
                       WHERE t.project_id = ?"""
            params: list = [project_id]
        else:
            query = "SELECT * FROM recon_data WHERE 1=1"
            params = []
        if target_id:
            query += " AND target_id = ?" if "rd." not in query else " AND rd.target_id = ?"
            params.append(target_id)
        if data_type:
            query += " AND data_type = ?" if "rd." not in query else " AND rd.data_type = ?"
            params.append(data_type)
        if source_tool:
            query += " AND source_tool = ?" if "rd." not in query else " AND rd.source_tool = ?"
            params.append(source_tool)
        query += f" ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_recon_summary(target_id: int = None, project_id: int = None,
                      db_path=None) -> dict:
    """Get count of recon data grouped by type."""
    with get_connection(db_path) as conn:
        if project_id:
            rows = conn.execute(
                """SELECT rd.data_type, COUNT(*) as cnt FROM recon_data rd
                   JOIN targets t ON rd.target_id = t.id
                   WHERE t.project_id = ?
                   GROUP BY rd.data_type ORDER BY cnt DESC""",
                (project_id,),
            ).fetchall()
        elif target_id:
            rows = conn.execute(
                """SELECT data_type, COUNT(*) as cnt FROM recon_data
                   WHERE target_id = ? GROUP BY data_type ORDER BY cnt DESC""",
                (target_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT data_type, COUNT(*) as cnt FROM recon_data GROUP BY data_type ORDER BY cnt DESC"
            ).fetchall()
    return {row["data_type"]: row["cnt"] for row in rows}


def delete_recon(recon_id: int, db_path=None):
    """Delete a single recon entry."""
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM recon_data WHERE id = ?", (recon_id,))
    log_action("deleted", "recon", recon_id, db_path=db_path)


def export_recon(target_id: int = None, project_id: int = None,
                 data_type: str = None, output_path: str = None,
                 db_path=None) -> str:
    """Export recon data to a text file (one value per line). Returns file path."""
    data = list_recon(target_id=target_id, data_type=data_type,
                      project_id=project_id, limit=100000, db_path=db_path)
    values = [d["value"] for d in data]
    if not output_path:
        from ..core.config import load_config
        cfg = load_config()
        output_path = str(Path(cfg["exports_dir"]) / f"recon_{data_type or 'all'}.txt")
    Path(output_path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    Path(output_path).write_text("\n".join(values) + "\n")
    log_action("exported", "recon", None,
               {"count": len(values), "file": output_path}, db_path)
    return output_path


# ---------------------------------------------------------------------------
# Tool integrations — parse output from common Kali tools
# ---------------------------------------------------------------------------

def _validate_target(value: str) -> str:
    """Validate a target value (domain, IP, CIDR) is safe for external tools."""
    value = value.strip()
    if not value or not _SAFE_TARGET_RE.match(value):
        raise ValueError(f"Invalid target value: {value!r}")
    return value


def _validate_extra_args(extra_args: str) -> list[str]:
    """Validate and split extra CLI arguments for external tools."""
    if not extra_args or not extra_args.strip():
        return []
    if not _SAFE_EXTRA_ARGS_RE.match(extra_args):
        raise ValueError(
            f"Unsafe characters in extra_args: {extra_args!r}. "
            f"Only alphanumerics, spaces, hyphens, dots, colons, commas, slashes, @, = are allowed."
        )
    return shlex.split(extra_args)


def ingest_subfinder(target_id: int, domain: str, extra_args: str = "",
                     timeout: int = 300, db_path=None) -> int:
    """Run subfinder and ingest results."""
    domain = _validate_target(domain)
    cmd = ["subfinder", "-d", domain, "-silent"]
    if extra_args:
        cmd.extend(_validate_extra_args(extra_args))
    rc, stdout, stderr = run_tool(cmd, timeout=timeout)
    if rc != 0 and not stdout.strip():
        raise RuntimeError(f"subfinder failed: {stderr}")
    subs = [line.strip() for line in stdout.splitlines() if line.strip()]
    return bulk_add_recon(target_id, "subdomain", subs, source_tool="subfinder", db_path=db_path)


def ingest_nmap(target_id: int, target_value: str, extra_args: str = "-sV -sC",
                timeout: int = 600, db_path=None) -> int:
    """Run nmap and ingest open ports/services."""
    target_value = _validate_target(target_value)
    cmd = ["nmap"]
    if extra_args:
        cmd.extend(_validate_extra_args(extra_args))
    cmd.extend([target_value, "-oG", "-"])
    rc, stdout, stderr = run_tool(cmd, timeout=timeout)
    count = 0
    for line in stdout.splitlines():
        if "/open/" in line:
            # Parse grepable nmap output
            parts = line.split()
            for part in parts:
                if "/open/" in part:
                    port_info = part.split("/")
                    port = port_info[0]
                    proto = port_info[2] if len(port_info) > 2 else ""
                    service = port_info[4] if len(port_info) > 4 else ""
                    add_recon(target_id, "port", f"{port}/{proto}",
                              source_tool="nmap", db_path=db_path)
                    if service:
                        add_recon(target_id, "service", f"{port}:{service}",
                                  source_tool="nmap", db_path=db_path)
                    count += 1
    # Store full raw output
    add_recon(target_id, "other", f"nmap_scan_{target_value}",
              source_tool="nmap", raw_output=stdout, db_path=db_path)
    return count


def ingest_httpx(target_id: int, input_file: str = None, targets: list[str] = None,
                 extra_args: str = "-silent -status-code -title -tech-detect",
                 timeout: int = 300, db_path=None) -> int:
    """Run httpx and ingest live URLs and tech data."""
    import subprocess as _subprocess

    extra = _validate_extra_args(extra_args) if extra_args else []
    if input_file:
        cmd = ["httpx", "-l", str(input_file)] + extra
        rc, stdout, stderr = run_tool(cmd, timeout=timeout)
    elif targets:
        validated = [_validate_target(t) for t in targets]
        target_str = "\n".join(validated)
        cmd = ["httpx"] + extra
        try:
            proc = _subprocess.run(
                cmd, input=target_str, capture_output=True,
                text=True, timeout=timeout,
            )
            rc, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except _subprocess.TimeoutExpired:
            rc, stdout, stderr = -1, "", f"httpx timed out after {timeout}s"
        except FileNotFoundError:
            rc, stdout, stderr = -1, "", "Command not found: httpx"
    else:
        return 0
    count = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # httpx outputs URL [status] [title] [tech...]
        parts = line.split()
        if parts:
            url = parts[0]
            add_recon(target_id, "url", url, source_tool="httpx", db_path=db_path)
            count += 1
    return count


def ingest_from_file(target_id: int, file_path: str, data_type: str,
                     source_tool: str = None, db_path=None) -> int:
    """Import recon data from a text file (one item per line)."""
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    values = [line.strip() for line in p.read_text().splitlines()
              if line.strip() and not line.startswith("#")]
    return bulk_add_recon(target_id, data_type, values, source_tool=source_tool, db_path=db_path)
