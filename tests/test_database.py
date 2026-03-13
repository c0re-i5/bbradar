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
            "targets", "vulns", "workflow_runs",
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
