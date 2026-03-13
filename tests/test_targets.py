"""
Tests for targets module.
"""

import pytest
from bbradar.modules.projects import create_project
from bbradar.modules.targets import (
    add_target, list_targets, get_target, update_target,
    delete_target, VALID_ASSET_TYPES,
)


@pytest.fixture
def project(tmp_db):
    pid = create_project("TargetTest", db_path=tmp_db)
    return pid, tmp_db


class TestAddTarget:
    def test_basic(self, project):
        pid, db = project
        tid = add_target(pid, "domain", "example.com", db_path=db)
        assert tid > 0
        t = get_target(tid, db_path=db)
        assert t["value"] == "example.com"
        assert t["asset_type"] == "domain"

    def test_invalid_type(self, project):
        pid, db = project
        with pytest.raises(ValueError, match="asset_type"):
            add_target(pid, "notreal", "test.com", db_path=db)

    def test_duplicate_rejected(self, project):
        pid, db = project
        add_target(pid, "domain", "dup.com", db_path=db)
        with pytest.raises(Exception):
            add_target(pid, "domain", "dup.com", db_path=db)

    def test_all_asset_types(self, project):
        pid, db = project
        for at in VALID_ASSET_TYPES:
            tid = add_target(pid, at, f"test-{at}", db_path=db)
            assert tid > 0


class TestListTargets:
    def test_filter_by_project(self, tmp_db):
        p1 = create_project("P1", db_path=tmp_db)
        p2 = create_project("P2", db_path=tmp_db)
        add_target(p1, "domain", "a.com", db_path=tmp_db)
        add_target(p2, "domain", "b.com", db_path=tmp_db)
        targets = list_targets(p1, db_path=tmp_db)
        assert len(targets) == 1
        assert targets[0]["value"] == "a.com"


class TestUpdateTarget:
    def test_update_scope(self, project):
        pid, db = project
        tid = add_target(pid, "domain", "test.com", db_path=db)
        update_target(tid, in_scope=False, db_path=db)
        t = get_target(tid, db_path=db)
        assert t["in_scope"] == 0
