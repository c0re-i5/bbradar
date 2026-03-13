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


class TestDeleteProject:
    def test_delete_cascades(self, tmp_db):
        from bbradar.modules.targets import add_target
        pid = create_project("ToDelete", db_path=tmp_db)
        add_target(pid, "domain", "test.com", db_path=tmp_db)
        delete_project(pid, db_path=tmp_db)
        assert get_project(pid, db_path=tmp_db) is None
