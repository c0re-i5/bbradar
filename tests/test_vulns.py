"""
Tests for vulnerability management module.
"""

import pytest
from bbradar.modules.projects import create_project
from bbradar.modules.targets import add_target
from bbradar.modules.vulns import (
    create_vuln, get_vuln, list_vulns, update_vuln, delete_vuln,
    get_vuln_stats, VALID_SEVERITIES, VALID_VULN_TYPES,
)


@pytest.fixture
def project(tmp_db):
    pid = create_project("VulnTest", db_path=tmp_db)
    return pid, tmp_db


class TestCreateVuln:
    def test_basic_create(self, project):
        pid, db = project
        vid = create_vuln(pid, "XSS in Search", severity="high", db_path=db)
        assert vid > 0
        v = get_vuln(vid, db_path=db)
        assert v["title"] == "XSS in Search"
        assert v["severity"] == "high"

    def test_all_fields(self, project):
        pid, db = project
        vid = create_vuln(
            pid, "SQLi in Login",
            severity="critical", vuln_type="sqli",
            description="Blind SQL injection", cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            db_path=db,
        )
        v = get_vuln(vid, db_path=db)
        assert v["vuln_type"] == "sqli"
        assert v["cvss_score"] == 9.8

    def test_invalid_severity(self, project):
        pid, db = project
        with pytest.raises(ValueError, match="severity"):
            create_vuln(pid, "Bad", severity="banana", db_path=db)

    def test_invalid_vuln_type(self, project):
        pid, db = project
        with pytest.raises(ValueError, match="vuln_type"):
            create_vuln(pid, "Bad", vuln_type="notreal", db_path=db)

    def test_nonexistent_project(self, tmp_db):
        with pytest.raises(Exception):
            create_vuln(999, "Test", db_path=tmp_db)


class TestListVulns:
    def test_filter_by_severity(self, project):
        pid, db = project
        create_vuln(pid, "Critical Bug", severity="critical", db_path=db)
        create_vuln(pid, "Low Bug", severity="low", db_path=db)
        high_plus = list_vulns(project_id=pid, severity="critical", db_path=db)
        assert len(high_plus) == 1

    def test_empty_list(self, project):
        pid, db = project
        assert list_vulns(project_id=pid, db_path=db) == []


class TestVulnStats:
    def test_stats_structure(self, project):
        pid, db = project
        create_vuln(pid, "High1", severity="high", db_path=db)
        create_vuln(pid, "High2", severity="high", db_path=db)
        create_vuln(pid, "Low1", severity="low", db_path=db)
        stats = get_vuln_stats(project_id=pid, db_path=db)
        assert stats["total"] == 3
        assert stats["by_severity"]["high"] == 2
        assert stats["by_severity"]["low"] == 1


class TestDeleteVuln:
    def test_delete(self, project):
        pid, db = project
        vid = create_vuln(pid, "ToDelete", db_path=db)
        delete_vuln(vid, db_path=db)
        assert get_vuln(vid, db_path=db) is None
