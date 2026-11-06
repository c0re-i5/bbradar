"""
Tests for core database module — schema, connections, migrations, backup/restore.
"""

import sqlite3
import pytest

from bbradar.core.database import (
    init_db, get_connection, get_schema_version,
    backup_db, restore_db, migrate_db, MIGRATIONS,
)


class TestInitDB:
    def test_creates_all_tables(self, tmp_db):
        with get_connection(tmp_db) as conn:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()]
        expected = [
            "audit_log", "kb_capec", "kb_cwe", "kb_nuclei", "kb_sync", "kb_vrt",
            "notes", "projects", "recon_data", "reports", "scope_rules",
            "scan_runs", "targets", "vulns", "workflow_runs",
        ]
        for t in expected:
            assert t in tables, f"Missing table: {t}"

    def test_foreign_keys_enabled(self, tmp_db):
        with get_connection(tmp_db) as conn:
            fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1

    def test_wal_mode(self, tmp_db):
        with get_connection(tmp_db) as conn:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"

    def test_schema_version_set(self, tmp_db):
        v = get_schema_version(tmp_db)
        assert v == MIGRATIONS[-1][0] if MIGRATIONS else v == 0


class TestConnection:
    def test_rollback_on_error(self, tmp_db):
        """Verify transactions roll back on exception."""
        with get_connection(tmp_db) as conn:
            conn.execute("INSERT INTO projects (name) VALUES ('rollback_test')")

        # This should fail and roll back
        with pytest.raises(Exception):
            with get_connection(tmp_db) as conn:
                conn.execute("INSERT INTO projects (name) VALUES ('will_fail')")
                raise RuntimeError("forced error")

        # 'will_fail' should NOT be in the DB
        with get_connection(tmp_db) as conn:
            rows = conn.execute("SELECT name FROM projects").fetchall()
        names = [r[0] for r in rows]
        assert "rollback_test" in names
        assert "will_fail" not in names


class TestBackupRestore:
    def test_backup_creates_file(self, tmp_db, tmp_path):
        with get_connection(tmp_db) as conn:
            conn.execute("INSERT INTO projects (name) VALUES ('backup_test')")

        backup_path = str(tmp_path / "backup.db")
        result = backup_db(output_path=backup_path, db_path=tmp_db)
        assert result == backup_path

        # Verify backup has the data
        c = sqlite3.connect(backup_path)
        rows = c.execute("SELECT name FROM projects").fetchall()
        c.close()
        assert any(r[0] == "backup_test" for r in rows)

    def test_restore_overwrites_db(self, tmp_db, tmp_path):
        # Create backup with data
        with get_connection(tmp_db) as conn:
            conn.execute("INSERT INTO projects (name) VALUES ('original')")
        backup_path = str(tmp_path / "backup.db")
        backup_db(output_path=backup_path, db_path=tmp_db)

        # Modify current DB
        with get_connection(tmp_db) as conn:
            conn.execute("INSERT INTO projects (name) VALUES ('modified')")

        # Restore from backup
        restore_db(backup_path, db_path=tmp_db)

        with get_connection(tmp_db) as conn:
            rows = conn.execute("SELECT name FROM projects").fetchall()
        names = [r[0] for r in rows]
        assert "original" in names
        assert "modified" not in names

    def test_restore_invalid_file(self, tmp_db, tmp_path):
        bad_file = tmp_path / "notadb.db"
        bad_file.write_text("this is not a database")
        with pytest.raises(ValueError, match="Invalid backup file"):
            restore_db(str(bad_file), db_path=tmp_db)

    def test_restore_missing_file(self, tmp_db):
        with pytest.raises(FileNotFoundError):
            restore_db("/nonexistent/path.db", db_path=tmp_db)


class TestMigrations:
    def test_migrate_idempotent(self, tmp_db):
        """Running migrate twice should be safe."""
        result1 = migrate_db(tmp_db)
        result2 = migrate_db(tmp_db)
        # Second run should find nothing to apply
        assert result2 == []

    def test_migration_8_from_v7(self, tmp_path):
        """v7 databases gain scan_runs, sync errors, and status guards."""
        db = tmp_path / "v7.db"
        conn = sqlite3.connect(db)
        conn.execute("PRAGMA user_version = 7")
        conn.executescript("""
            CREATE TABLE projects (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'active'
            );
            CREATE TABLE targets (
                id INTEGER PRIMARY KEY
            );
            INSERT INTO projects (name, status) VALUES ('Legacy', 'Active');
            CREATE TABLE workflow_runs (
                id INTEGER PRIMARY KEY,
                workflow_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running'
            );
            CREATE TABLE kb_sync (
                source TEXT PRIMARY KEY,
                last_sync TEXT,
                etag TEXT,
                last_modified TEXT,
                record_count INTEGER,
                file_hash TEXT
            );
            CREATE TABLE h1_watched_programs (
                id INTEGER PRIMARY KEY,
                handle TEXT NOT NULL UNIQUE,
                name TEXT
            );
            CREATE TABLE h1_hacktivity_cache (
                id INTEGER PRIMARY KEY,
                h1_report_id TEXT NOT NULL,
                handle TEXT NOT NULL,
                UNIQUE(h1_report_id)
            );
            INSERT INTO h1_watched_programs (handle, name) VALUES ('seeded', 'S');
            INSERT INTO h1_hacktivity_cache (h1_report_id, handle) VALUES ('1', 'seeded');
        """)
        conn.commit()
        conn.close()

        applied = migrate_db(str(db))
        assert any(item.startswith("v8:") for item in applied)

        conn = sqlite3.connect(db)
        assert conn.execute("SELECT status FROM projects").fetchone()[0] == "active"
        cols = {row[1] for row in conn.execute("PRAGMA table_info(kb_sync)")}
        assert "last_error" in cols
        assert "last_status" in cols
        seeded = conn.execute(
            "SELECT hacktivity_seeded FROM h1_watched_programs"
        ).fetchone()[0]
        assert seeded == 1
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        assert "scan_runs" in tables
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE projects SET status = 'nope'")
        conn.close()


class TestKbSyncErrorStatus:
    def test_last_error_surfaces_and_clears(self, tmp_db):
        from unittest.mock import patch
        from bbradar.modules import knowledgebase
        with patch.object(
            knowledgebase, "sync_cwe",
            return_value={"source": "cwe", "status": "error", "reason": "boom", "records": 0},
        ):
            knowledgebase.sync_all(sources=["cwe"], db_path=tmp_db)
        rows = {r["source"]: r for r in knowledgebase.get_sync_status(db_path=tmp_db)}
        assert rows["cwe"]["last_error"] == "boom"
        assert rows["cwe"]["last_status"] == "error"
        knowledgebase._set_sync_info("cwe", 3, db_path=tmp_db)
        rows = {r["source"]: r for r in knowledgebase.get_sync_status(db_path=tmp_db)}
        assert not rows["cwe"]["last_error"]
