"""
Tests for Phase 7 features:
  - Status transition state machine
  - Vuln dedup/merge
  - Audit log management (stats, purge, export)
  - Evidence management
  - Workflow pre-flight checks
  - REST API
"""

import json
import os
import pytest

from bbradar.modules.projects import create_project
from bbradar.modules.vulns import (
    create_vuln, get_vuln, update_vuln, get_allowed_transitions,
    find_duplicates, merge_vulns, STATUS_TRANSITIONS,
)
from bbradar.modules.notes import create_note, list_notes
from bbradar.core.audit import (
    log_action, get_audit_log, get_audit_stats,
    purge_audit_log, export_audit_log,
)
from bbradar.modules.evidence import (
    get_evidence_dir, list_evidence_files, get_referenced_evidence,
    find_orphaned_files, cleanup_orphans, check_file_size, get_evidence_stats,
)


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture
def project(tmp_db):
    pid = create_project("TestProject", db_path=tmp_db)
    return pid, tmp_db


@pytest.fixture
def two_vulns(project):
    pid, db = project
    v1 = create_vuln(pid, "XSS in Search", severity="high", vuln_type="xss", db_path=db)
    v2 = create_vuln(pid, "XSS in Search", severity="medium", vuln_type="xss",
                     cvss_score=5.0, db_path=db)
    return v1, v2, pid, db


# ══════════════════════════════════════════════════════════════
# Status Transition State Machine
# ══════════════════════════════════════════════════════════════

class TestStatusTransitions:
    def test_valid_transition_new_to_confirmed(self, project):
        pid, db = project
        vid = create_vuln(pid, "Test", db_path=db)
        assert get_vuln(vid, db)["status"] == "new"
        update_vuln(vid, status="confirmed", db_path=db)
        assert get_vuln(vid, db)["status"] == "confirmed"

    def test_valid_transition_confirmed_to_reported(self, project):
        pid, db = project
        vid = create_vuln(pid, "Test", db_path=db)
        update_vuln(vid, status="confirmed", db_path=db)
        update_vuln(vid, status="reported", db_path=db)
        assert get_vuln(vid, db)["status"] == "reported"

    def test_invalid_transition_new_to_accepted(self, project):
        pid, db = project
        vid = create_vuln(pid, "Test", db_path=db)
        with pytest.raises(ValueError, match="Cannot transition"):
            update_vuln(vid, status="accepted", db_path=db)

    def test_invalid_transition_new_to_resolved(self, project):
        pid, db = project
        vid = create_vuln(pid, "Test", db_path=db)
        with pytest.raises(ValueError, match="Cannot transition"):
            update_vuln(vid, status="resolved", db_path=db)

    def test_reopen_from_resolved(self, project):
        pid, db = project
        vid = create_vuln(pid, "Test", db_path=db)
        update_vuln(vid, status="confirmed", db_path=db)
        update_vuln(vid, status="reported", db_path=db)
        update_vuln(vid, status="resolved", db_path=db)
        # Reopen
        update_vuln(vid, status="new", db_path=db)
        assert get_vuln(vid, db)["status"] == "new"

    def test_reopen_from_wontfix(self, project):
        pid, db = project
        vid = create_vuln(pid, "Test", db_path=db)
        update_vuln(vid, status="wontfix", db_path=db)
        update_vuln(vid, status="new", db_path=db)
        assert get_vuln(vid, db)["status"] == "new"

    def test_same_status_update_allowed(self, project):
        pid, db = project
        vid = create_vuln(pid, "Test", db_path=db)
        # Same status should not fail
        update_vuln(vid, status="new", db_path=db)
        assert get_vuln(vid, db)["status"] == "new"

    def test_get_allowed_transitions(self, project):
        pid, db = project
        vid = create_vuln(pid, "Test", db_path=db)
        allowed = get_allowed_transitions(vid, db)
        assert "confirmed" in allowed
        assert "duplicate" in allowed
        assert "accepted" not in allowed

    def test_get_allowed_transitions_nonexistent(self, tmp_db):
        allowed = get_allowed_transitions(9999, tmp_db)
        assert allowed == []

    def test_full_happy_path(self, project):
        """Test the full lifecycle: new→confirmed→reported→accepted→resolved."""
        pid, db = project
        vid = create_vuln(pid, "Test", db_path=db)
        for status in ["confirmed", "reported", "accepted", "resolved"]:
            update_vuln(vid, status=status, db_path=db)
            assert get_vuln(vid, db)["status"] == status

    def test_all_transitions_match_valid_statuses(self):
        """Verify no ghost statuses in the transition map."""
        from bbradar.modules.vulns import VALID_STATUSES
        for src, dests in STATUS_TRANSITIONS.items():
            assert src in VALID_STATUSES
            for d in dests:
                assert d in VALID_STATUSES


# ══════════════════════════════════════════════════════════════
# Vuln Dedup / Merge
# ══════════════════════════════════════════════════════════════

class TestFindDuplicates:
    def test_find_by_title(self, two_vulns):
        v1, v2, pid, db = two_vulns
        dupes = find_duplicates(v1, db)
        assert len(dupes) >= 1
        assert any(d["id"] == v2 for d in dupes)

    def test_no_duplicates(self, project):
        pid, db = project
        vid = create_vuln(pid, "Unique Finding", severity="low", db_path=db)
        dupes = find_duplicates(vid, db)
        assert dupes == []

    def test_find_nonexistent(self, tmp_db):
        assert find_duplicates(9999, tmp_db) == []


class TestMergeVulns:
    def test_basic_merge(self, two_vulns):
        v1, v2, pid, db = two_vulns
        ok = merge_vulns(v1, v2, db)
        assert ok
        # Source marked as duplicate
        assert get_vuln(v1, db)["status"] == "duplicate"
        # Target severity takes the higher one (high > medium)
        assert get_vuln(v2, db)["severity"] == "high"

    def test_merge_combines_notes(self, two_vulns):
        v1, v2, pid, db = two_vulns
        create_note("Note on v1", vuln_id=v1, db_path=db)
        merge_vulns(v1, v2, db)
        target_notes = list_notes(vuln_id=v2, db_path=db)
        assert len(target_notes) == 1

    def test_merge_nonexistent(self, project):
        pid, db = project
        assert not merge_vulns(9999, 9998, db)


# ══════════════════════════════════════════════════════════════
# Audit Log Management
# ══════════════════════════════════════════════════════════════

class TestAuditStats:
    def test_stats_structure(self, tmp_db):
        log_action("test_action", "test", 1, {"key": "val"}, tmp_db)
        log_action("test_action", "test", 2, {"key": "val2"}, tmp_db)
        s = get_audit_stats(tmp_db)
        assert s["total"] >= 2
        assert "test_action" in s["by_action"]

    def test_stats_empty(self, tmp_db):
        s = get_audit_stats(tmp_db)
        # May have entries from init, but structure should still be valid
        assert "total" in s
        assert "by_action" in s


class TestAuditPurge:
    def test_purge_nothing(self, tmp_db):
        """Fresh entries should not be purged."""
        log_action("recent", "test", 1, db_path=tmp_db)
        deleted = purge_audit_log(days=90, db_path=tmp_db)
        assert deleted == 0
        assert len(get_audit_log(db_path=tmp_db)) >= 1

    def test_purge_old_entries(self, tmp_db):
        """Entries inserted manually in the past should be purgeable."""
        from bbradar.core.database import get_connection
        with get_connection(tmp_db) as conn:
            conn.execute(
                "INSERT INTO audit_log (action, entity_type, entity_id, timestamp) "
                "VALUES (?, ?, ?, datetime('now', '-100 days'))",
                ("old_action", "test", 1),
            )
            conn.execute(
                "INSERT INTO audit_log (action, entity_type, entity_id, timestamp) "
                "VALUES (?, ?, ?, datetime('now', '-100 days'))",
                ("old_action2", "test", 2),
            )
        deleted = purge_audit_log(days=90, db_path=tmp_db)
        assert deleted == 2


class TestAuditExport:
    def test_export_to_file(self, tmp_db, tmp_path):
        log_action("exp_action", "test", 1, {"data": "test"}, tmp_db)
        out = str(tmp_path / "audit_export.json")
        result = export_audit_log(out, db_path=tmp_db)
        assert result == out
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) >= 1


# ══════════════════════════════════════════════════════════════
# Evidence Management
# ══════════════════════════════════════════════════════════════

class TestEvidenceFileSizeCheck:
    def test_small_file_ok(self, tmp_path):
        f = tmp_path / "small.png"
        f.write_bytes(b"x" * 100)
        assert check_file_size(str(f))

    def test_large_file_rejected(self, tmp_path):
        f = tmp_path / "large.bin"
        # Just check the logic without creating a 50MB file
        f.write_bytes(b"x" * 100)
        assert not check_file_size(str(f), max_bytes=50)


class TestEvidenceStats:
    def test_stats_structure(self, tmp_db):
        s = get_evidence_stats(tmp_db)
        assert "total_files" in s
        assert "total_size" in s
        assert "referenced" in s
        assert "orphaned" in s


class TestOrphanDetection:
    def test_no_orphans_when_empty(self, tmp_db):
        orphans = find_orphaned_files(tmp_db)
        # Evidence dir may not exist → empty
        assert orphans == []
