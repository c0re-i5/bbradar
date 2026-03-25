"""
Database layer for BBRadar.

Uses SQLite for local, portable storage. All data stays on disk under
the workspace directory — no external services required.
"""

import sqlite3
import os
from contextlib import contextmanager
from pathlib import Path

# Default data directory
DEFAULT_DATA_DIR = Path.home() / ".bbradar"


def get_db_path(data_dir: Path | None = None) -> Path:
    """Return the path to the SQLite database file."""
    base = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    return base / "bbradar.db"


@contextmanager
def get_connection(db_path: Path | None = None):
    """Context manager yielding a database connection with WAL mode and foreign keys."""
    path = db_path or get_db_path()
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")  # wait up to 5s for locks
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Path | None = None):
    """Create all tables if they don't exist."""
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA)
    # Set version to latest migration
    if MIGRATIONS:
        p = db_path or get_db_path()
        c = sqlite3.connect(str(p))
        _set_schema_version(c, MIGRATIONS[-1][0])
        c.commit()
        c.close()


def backup_db(output_path: str = None, db_path=None) -> str:
    """
    Create a backup of the database using SQLite online backup API.
    Returns the path to the backup file.
    """
    import shutil
    from datetime import datetime

    src = db_path or get_db_path()
    if not Path(src).exists():
        raise FileNotFoundError("No database found to back up")

    if not output_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = DEFAULT_DATA_DIR / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        output_path = str(backup_dir / f"bbradar_backup_{ts}.db")

    # Use SQLite backup API for a consistent snapshot
    src_conn = sqlite3.connect(str(src))
    dst_conn = sqlite3.connect(output_path)
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()

    return output_path


def restore_db(backup_path: str, db_path=None) -> str:
    """
    Restore the database from a backup file.
    Returns the path to the restored database.
    """
    backup = Path(backup_path)
    if not backup.exists():
        raise FileNotFoundError(f"Backup file not found: {backup_path}")

    # Verify it's a valid SQLite database
    try:
        c = sqlite3.connect(str(backup))
        c.execute("SELECT count(*) FROM projects")
        c.close()
    except sqlite3.Error as e:
        raise ValueError(f"Invalid backup file: {e}")

    dest = db_path or get_db_path()

    # Backup current DB before overwriting
    if Path(dest).exists():
        pre_restore = str(dest) + ".pre-restore"
        src_conn = sqlite3.connect(str(dest))
        pre_conn = sqlite3.connect(pre_restore)
        try:
            src_conn.backup(pre_conn)
        finally:
            pre_conn.close()
            src_conn.close()

    # Restore
    src_conn = sqlite3.connect(str(backup))
    dst_conn = sqlite3.connect(str(dest))
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()

    return str(dest)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA = """
-- Projects represent bug bounty programs or assessment engagements
CREATE TABLE IF NOT EXISTS projects (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    platform        TEXT,                              -- e.g. HackerOne, Bugcrowd, Intigriti, private
    program_url     TEXT,
    h1_handle       TEXT,                              -- HackerOne program handle for watch/sync
    scope_raw       TEXT,                              -- raw scope text from program page
    rules           TEXT,                              -- rules of engagement notes
    status          TEXT    NOT NULL DEFAULT 'active',  -- active | paused | completed | archived
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Targets are individual assets under a project's scope
CREATE TABLE IF NOT EXISTS targets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_type      TEXT    NOT NULL,                   -- domain | ip | url | mobile_app | api | wildcard | other
    value           TEXT    NOT NULL,                   -- e.g. "*.example.com", "10.0.0.0/24"
    in_scope        INTEGER NOT NULL DEFAULT 1,         -- 1=in-scope, 0=out-of-scope
    tier            TEXT,                               -- priority tier: critical | high | medium | low
    notes           TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(project_id, asset_type, value)
);

-- Recon data collected during reconnaissance phase
CREATE TABLE IF NOT EXISTS recon_data (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    data_type       TEXT    NOT NULL,                   -- subdomain | port | service | tech | url | parameter | dns | whois | cert | screenshot | other
    value           TEXT    NOT NULL,
    source_tool     TEXT,                               -- which tool produced this data
    raw_output      TEXT,                               -- full tool output if desired
    confidence      TEXT    DEFAULT 'medium',           -- high | medium | low
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(target_id, data_type, value)
);

-- Vulnerabilities / findings
CREATE TABLE IF NOT EXISTS vulns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_id       INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    title           TEXT    NOT NULL,
    vuln_type       TEXT,                               -- xss | sqli | ssrf | idor | rce | info_disclosure | etc.
    severity        TEXT    NOT NULL DEFAULT 'medium',   -- critical | high | medium | low | informational
    cvss_score      REAL,
    cvss_vector     TEXT,
    description     TEXT,
    impact          TEXT,
    reproduction    TEXT,                               -- step-by-step reproduction
    evidence        TEXT,                               -- JSON: list of evidence file paths / screenshots
    request         TEXT,                               -- raw HTTP request
    response        TEXT,                               -- raw HTTP response (truncated)
    remediation     TEXT,
    status          TEXT    NOT NULL DEFAULT 'new',      -- new | confirmed | reported | accepted | duplicate | resolved | wontfix
    bounty_amount   REAL,
    report_url      TEXT,                               -- link to submitted report
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Notes linked to any entity
CREATE TABLE IF NOT EXISTS notes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    target_id       INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    vuln_id         INTEGER REFERENCES vulns(id) ON DELETE SET NULL,
    title           TEXT,
    content         TEXT    NOT NULL,
    tags            TEXT,                               -- comma-separated tags
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Audit log — every significant action is recorded
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    action          TEXT    NOT NULL,                   -- created | updated | deleted | exported | ran_tool | etc.
    entity_type     TEXT,                               -- project | target | recon | vuln | note | report | workflow
    entity_id       INTEGER,
    details         TEXT,                               -- JSON with action-specific details
    timestamp       TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Workflow runs
CREATE TABLE IF NOT EXISTS workflow_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_name   TEXT    NOT NULL,
    project_id      INTEGER REFERENCES projects(id) ON DELETE SET NULL,
    target_id       INTEGER REFERENCES targets(id) ON DELETE SET NULL,
    status          TEXT    NOT NULL DEFAULT 'running',  -- running | completed | failed | cancelled
    started_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    finished_at     TEXT,
    output_log      TEXT
);

-- Reports generated
CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    vuln_id         INTEGER REFERENCES vulns(id) ON DELETE SET NULL,
    report_type     TEXT    NOT NULL DEFAULT 'single',   -- single | full | executive
    format          TEXT    NOT NULL DEFAULT 'markdown', -- markdown | html | pdf
    file_path       TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id);
CREATE INDEX IF NOT EXISTS idx_recon_target ON recon_data(target_id);
CREATE INDEX IF NOT EXISTS idx_recon_type ON recon_data(data_type);
CREATE INDEX IF NOT EXISTS idx_vulns_project ON vulns(project_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulns(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulns(status);
CREATE INDEX IF NOT EXISTS idx_notes_project ON notes(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

-- ═══ Knowledge Base Tables ═══

-- CWE entries from MITRE
CREATE TABLE IF NOT EXISTS kb_cwe (
    cwe_id          TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT,
    extended_description TEXT,
    abstraction     TEXT,
    consequences    TEXT,
    mitigations     TEXT,
    detection_methods TEXT,
    related_cwes    TEXT,
    owasp_mappings  TEXT,
    capec_ids       TEXT
);

-- CAPEC attack patterns from MITRE
CREATE TABLE IF NOT EXISTS kb_capec (
    capec_id        TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    description     TEXT,
    likelihood      TEXT,
    severity        TEXT,
    prerequisites   TEXT,
    mitigations     TEXT,
    related_cwes    TEXT
);

-- Bugcrowd VRT entries
CREATE TABLE IF NOT EXISTS kb_vrt (
    path            TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    priority        INTEGER,
    category        TEXT,
    parent_path     TEXT
);

-- Nuclei template metadata
CREATE TABLE IF NOT EXISTS kb_nuclei (
    template_id     TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    severity        TEXT,
    description     TEXT,
    remediation     TEXT,
    tags            TEXT,
    cwe_id          TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    reference_urls TEXT,
    file_path       TEXT
);

-- KB sync log — tracks download state per source for caching
CREATE TABLE IF NOT EXISTS kb_sync (
    source          TEXT PRIMARY KEY,
    last_sync       TEXT,
    etag            TEXT,
    last_modified   TEXT,
    record_count    INTEGER,
    file_hash       TEXT
);

CREATE INDEX IF NOT EXISTS idx_kb_cwe_name ON kb_cwe(name);
CREATE INDEX IF NOT EXISTS idx_kb_capec_name ON kb_capec(name);
CREATE INDEX IF NOT EXISTS idx_kb_nuclei_severity ON kb_nuclei(severity);
CREATE INDEX IF NOT EXISTS idx_kb_nuclei_cwe ON kb_nuclei(cwe_id);

-- ═══ Scope Rules ═══

-- Structured scope rules for pattern-based matching
CREATE TABLE IF NOT EXISTS scope_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    rule_type       TEXT    NOT NULL DEFAULT 'include',  -- include | exclude
    pattern_type    TEXT    NOT NULL DEFAULT 'wildcard',  -- wildcard | cidr | regex | exact
    pattern         TEXT    NOT NULL,                     -- e.g. *.example.com, 10.0.0.0/24
    asset_category  TEXT,                                -- domain | ip | url | general (NULL=any)
    priority        INTEGER NOT NULL DEFAULT 0,          -- higher = evaluated later; excludes at same priority win
    notes           TEXT,
    source          TEXT,                                -- where rule came from: manual | hackerone | bugcrowd | import
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_scope_rules_project ON scope_rules(project_id);

-- ═══ HackerOne Watch ═══

-- Watched H1 programs for scope change detection
CREATE TABLE IF NOT EXISTS h1_watched_programs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    handle          TEXT    NOT NULL UNIQUE,
    name            TEXT,
    project_id      INTEGER REFERENCES projects(id) ON DELETE SET NULL,
    last_checked_at TEXT,
    last_changed_at TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Scope snapshots for diffing
CREATE TABLE IF NOT EXISTS h1_scope_snapshots (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    handle                  TEXT    NOT NULL,
    asset_identifier        TEXT    NOT NULL,
    asset_type              TEXT    NOT NULL,
    eligible_for_bounty     INTEGER NOT NULL DEFAULT 0,
    eligible_for_submission INTEGER NOT NULL DEFAULT 1,
    max_severity            TEXT,
    instruction             TEXT,
    snapshot_at             TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(handle, asset_identifier, asset_type)
);
CREATE INDEX IF NOT EXISTS idx_h1_snapshots_handle ON h1_scope_snapshots(handle);
""";


# ---------------------------------------------------------------------------
# Migrations — sequential schema upgrades for existing databases
# ---------------------------------------------------------------------------

# Each migration is (version_number, description, sql).
# Only new migrations are applied — the current version is tracked in a pragma.
MIGRATIONS = [
    (1, "Add scope_rules table", """
        CREATE TABLE IF NOT EXISTS scope_rules (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id      INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            rule_type       TEXT    NOT NULL DEFAULT 'include',
            pattern_type    TEXT    NOT NULL DEFAULT 'wildcard',
            pattern         TEXT    NOT NULL,
            asset_category  TEXT,
            priority        INTEGER NOT NULL DEFAULT 0,
            notes           TEXT,
            source          TEXT    NOT NULL DEFAULT 'manual',
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_scope_rules_project ON scope_rules(project_id);
    """),
    (2, "Add HackerOne watch tables and h1_handle column", """
        ALTER TABLE projects ADD COLUMN h1_handle TEXT;

        CREATE TABLE IF NOT EXISTS h1_watched_programs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            handle          TEXT    NOT NULL UNIQUE,
            name            TEXT,
            project_id      INTEGER REFERENCES projects(id) ON DELETE SET NULL,
            last_checked_at TEXT,
            last_changed_at TEXT,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS h1_scope_snapshots (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            handle                  TEXT    NOT NULL,
            asset_identifier        TEXT    NOT NULL,
            asset_type              TEXT    NOT NULL,
            eligible_for_bounty     INTEGER NOT NULL DEFAULT 0,
            eligible_for_submission INTEGER NOT NULL DEFAULT 1,
            max_severity            TEXT,
            instruction             TEXT,
            snapshot_at             TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(handle, asset_identifier, asset_type)
        );
        CREATE INDEX IF NOT EXISTS idx_h1_snapshots_handle ON h1_scope_snapshots(handle);
    """),
]


def get_schema_version(db_path=None) -> int:
    """Return the current schema migration version."""
    path = db_path or get_db_path()
    conn = sqlite3.connect(str(path))
    try:
        v = conn.execute("PRAGMA user_version").fetchone()[0]
        return v
    finally:
        conn.close()


def _set_schema_version(conn, version: int):
    """Set the schema version pragma (must be run outside executescript)."""
    conn.execute(f"PRAGMA user_version = {int(version)}")


def migrate_db(db_path=None) -> list[str]:
    """
    Apply any pending migrations. Returns list of applied migration descriptions.
    Safe to run multiple times — already-applied migrations are skipped.
    """
    path = db_path or get_db_path()
    if not Path(path).exists():
        return []

    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA foreign_keys=ON")
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    applied = []

    try:
        for version, description, sql in MIGRATIONS:
            if version > current:
                conn.executescript(sql)
                _set_schema_version(conn, version)
                conn.commit()
                current = version
                applied.append(f"v{version}: {description}")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return applied