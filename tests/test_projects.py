"""
Tests for project management module.
"""

import pytest
from bbradar.modules.projects import (
    create_project, get_project, list_projects, update_project, delete_project,
)


class TestCreateProject:
    def test_basic_create(self, tmp_db):
        pid = create_project("Test Project", db_path=tmp_db)
        assert pid > 0

    def test_create_with_all_fields(self, tmp_db):
        pid = create_project(
            "Full Project", platform="hackerone",
            program_url="https://hackerone.com/test",
            scope_raw="*.example.com", rules="No DoS",
            db_path=tmp_db,
        )
        p = get_project(pid, db_path=tmp_db)
        assert p["name"] == "Full Project"
        assert p["platform"] == "hackerone"
        assert p["scope_raw"] == "*.example.com"

    def test_empty_name_rejected(self, tmp_db):
        with pytest.raises(ValueError, match="cannot be empty"):
            create_project("", db_path=tmp_db)

    def test_whitespace_name_rejected(self, tmp_db):
        with pytest.raises(ValueError, match="cannot be empty"):
            create_project("   ", db_path=tmp_db)

    def test_duplicate_name_rejected(self, tmp_db):
        create_project("Duplicate", db_path=tmp_db)
        with pytest.raises(Exception):
            create_project("Duplicate", db_path=tmp_db)

    def test_special_characters_in_name(self, tmp_db):
        pid = create_project("Test's <Project> & \"More\"", db_path=tmp_db)
        p = get_project(pid, db_path=tmp_db)
        assert p["name"] == "Test's <Project> & \"More\""


class TestListProjects:
    def test_list_empty(self, tmp_db):
        result = list_projects(db_path=tmp_db)
        assert result == []

    def test_list_with_status_filter(self, tmp_db):
        create_project("Active", db_path=tmp_db)
        p2 = create_project("Paused", db_path=tmp_db)
        update_project(p2, status="paused", db_path=tmp_db)

        active = list_projects(status="active", db_path=tmp_db)
        assert len(active) == 1
        assert active[0]["name"] == "Active"


class TestProjectStatus:
    def test_rejects_unknown_status(self, tmp_db):
        pid = create_project("Status", db_path=tmp_db)
        with pytest.raises(ValueError, match="Invalid project status"):
            update_project(pid, status="nope", db_path=tmp_db)

    def test_normalizes_case(self, tmp_db):
        pid = create_project("Status", db_path=tmp_db)
        update_project(pid, status="Paused", db_path=tmp_db)
        assert get_project(pid, db_path=tmp_db)["status"] == "paused"
        paused = list_projects(status="PAUSED", db_path=tmp_db)
        assert [p["id"] for p in paused] == [pid]

    def test_check_constraint_rejects_raw_invalid_status(self, tmp_db):
        from bbradar.core.database import get_connection
        pid = create_project("Status", db_path=tmp_db)
        with pytest.raises(Exception):
            with get_connection(tmp_db) as conn:
                conn.execute("UPDATE projects SET status = 'Active' WHERE id = ?", (pid,))

    def test_archived_rejects_new_findings_and_targets(self, tmp_db):
        from bbradar.modules.targets import add_target
        from bbradar.modules.vulns import create_vuln, update_vuln, get_vuln
        pid = create_project("Archived", db_path=tmp_db)
        vid = create_vuln(pid, "Existing", db_path=tmp_db)
        update_project(pid, status="archived", db_path=tmp_db)
        with pytest.raises(ValueError, match="only allowed while the project is active"):
            create_vuln(pid, "Too late", db_path=tmp_db)
        with pytest.raises(ValueError, match="only allowed while the project is active"):
            add_target(pid, "domain", "late.example.com", db_path=tmp_db)
        # Existing findings can still move through their status machine.
        update_vuln(vid, status="confirmed", db_path=tmp_db)
        assert get_vuln(vid, db_path=tmp_db)["status"] == "confirmed"

    def test_paused_rejects_new_targets(self, tmp_db):
        from bbradar.modules.targets import add_target
        pid = create_project("Paused", db_path=tmp_db)
        update_project(pid, status="paused", db_path=tmp_db)
        with pytest.raises(ValueError, match="paused"):
            add_target(pid, "domain", "paused.example.com", db_path=tmp_db)

    def test_completed_rejects_new_findings(self, tmp_db):
        from bbradar.modules.vulns import create_vuln
        pid = create_project("Done", db_path=tmp_db)
        update_project(pid, status="completed", db_path=tmp_db)
        with pytest.raises(ValueError, match="completed"):
            create_vuln(pid, "After close", db_path=tmp_db)

    def test_dashboard_treats_mixed_case_active_as_active(self):
        from bbradar.modules.projects import project_status_of
        assert project_status_of({"status": "Active"}) == "active"
        assert project_status_of({"status": " archived "}) == "archived"


class TestDeleteProject:
    def test_delete_cascades(self, tmp_db):
        from bbradar.modules.targets import add_target
        pid = create_project("ToDelete", db_path=tmp_db)
        add_target(pid, "domain", "test.com", db_path=tmp_db)
        delete_project(pid, db_path=tmp_db)
        assert get_project(pid, db_path=tmp_db) is None
