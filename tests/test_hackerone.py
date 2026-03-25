"""
Tests for HackerOne integration module.

Tests the local integration functions (import_program, sync_scope,
dashboard) using mock API responses, and verifies the data mapping
and credential management logic.
"""

import json
from unittest.mock import patch, MagicMock

import pytest

from bbradar.modules import hackerone
from bbradar.modules.projects import get_project, list_projects
from bbradar.modules.targets import list_targets
from bbradar.modules.scope import list_rules
from bbradar.modules.vulns import create_vuln


# ═══════════════════════════════════════════════════════════════════
# Mock API response builders
# ═══════════════════════════════════════════════════════════════════

def _mock_program_response(handle="testprog", name="Test Program"):
    """Build a mock H1 program API response."""
    return {
        "data": {
            "id": "12345",
            "attributes": {
                "handle": handle,
                "name": name,
                "offers_bounties": True,
                "policy": "Do not test admin panel.",
                "state": "public_mode",
            },
            "relationships": {
                "structured_scopes": {
                    "data": [
                        {
                            "attributes": {
                                "asset_identifier": "*.example.com",
                                "asset_type": "WILDCARD",
                                "eligible_for_bounty": True,
                                "eligible_for_submission": True,
                                "instruction": "Main wildcard",
                                "max_severity": "critical",
                            }
                        },
                        {
                            "attributes": {
                                "asset_identifier": "https://api.example.com",
                                "asset_type": "URL",
                                "eligible_for_bounty": True,
                                "eligible_for_submission": True,
                                "instruction": "API endpoint",
                                "max_severity": "critical",
                            }
                        },
                        {
                            "attributes": {
                                "asset_identifier": "admin.example.com",
                                "asset_type": "DOMAIN",
                                "eligible_for_bounty": False,
                                "eligible_for_submission": False,
                                "instruction": "Out of scope",
                                "max_severity": "",
                            }
                        },
                    ]
                }
            },
        }
    }


def _mock_programs_list_response():
    """Build a mock H1 programs list response."""
    return {
        "data": [
            {
                "id": "1",
                "attributes": {
                    "handle": "prog-a",
                    "name": "Program A",
                    "offers_bounties": True,
                    "state": "public_mode",
                    "started_accepting_at": "2024-01-01T00:00:00Z",
                    "submission_state": "open",
                    "bookmarked": False,
                },
            },
            {
                "id": "2",
                "attributes": {
                    "handle": "prog-b",
                    "name": "Program B",
                    "offers_bounties": False,
                    "state": "public_mode",
                    "started_accepting_at": "2024-06-01T00:00:00Z",
                    "submission_state": "open",
                    "bookmarked": True,
                },
            },
        ],
        "links": {},
    }


def _mock_reports_response():
    """Build a mock H1 reports list response."""
    return {
        "data": [
            {
                "id": "100001",
                "attributes": {
                    "title": "XSS on search",
                    "state": "resolved",
                    "substate": "resolved",
                    "severity_rating": "high",
                    "bounty_awarded_at": "2025-03-01T12:00:00Z",
                    "created_at": "2025-02-15T10:00:00Z",
                    "disclosed_at": None,
                    "triaged_at": "2025-02-16T10:00:00Z",
                    "closed_at": "2025-03-01T12:00:00Z",
                },
            },
            {
                "id": "100002",
                "attributes": {
                    "title": "IDOR on /api/users",
                    "state": "triaged",
                    "substate": "triaged",
                    "severity_rating": "medium",
                    "bounty_awarded_at": None,
                    "created_at": "2025-03-10T10:00:00Z",
                    "disclosed_at": None,
                    "triaged_at": "2025-03-11T10:00:00Z",
                    "closed_at": None,
                },
            },
        ],
        "links": {},
    }


def _mock_balance_response():
    return {
        "data": {
            "attributes": {
                "balance": "1250.00",
                "currency": "USD",
            }
        }
    }


def _mock_earnings_response():
    return {
        "data": [
            {
                "id": "e1",
                "attributes": {
                    "amount": "500.00",
                    "currency": "USD",
                    "awarded_at": "2025-03-01T00:00:00Z",
                    "bounty_type": "bounty",
                },
            },
            {
                "id": "e2",
                "attributes": {
                    "amount": "750.00",
                    "currency": "USD",
                    "awarded_at": "2025-02-15T00:00:00Z",
                    "bounty_type": "bounty",
                },
            },
        ],
        "links": {},
    }


# ═══════════════════════════════════════════════════════════════════
# Tests: Asset type mapping
# ═══════════════════════════════════════════════════════════════════

class TestAssetTypeMapping:
    def test_known_types(self):
        assert hackerone.H1_ASSET_TYPE_MAP["URL"] == "url"
        assert hackerone.H1_ASSET_TYPE_MAP["DOMAIN"] == "domain"
        assert hackerone.H1_ASSET_TYPE_MAP["WILDCARD"] == "wildcard"
        assert hackerone.H1_ASSET_TYPE_MAP["CIDR"] == "cidr"
        assert hackerone.H1_ASSET_TYPE_MAP["IP_ADDRESS"] == "ip"
        assert hackerone.H1_ASSET_TYPE_MAP["API"] == "api"

    def test_mobile_types(self):
        assert hackerone.H1_ASSET_TYPE_MAP["GOOGLE_PLAY_APP_ID"] == "mobile_app"
        assert hackerone.H1_ASSET_TYPE_MAP["APPLE_STORE_APP_ID"] == "mobile_app"

    def test_other_fallback(self):
        assert hackerone.H1_ASSET_TYPE_MAP["SOURCE_CODE"] == "other"
        assert hackerone.H1_ASSET_TYPE_MAP["HARDWARE"] == "other"


# ═══════════════════════════════════════════════════════════════════
# Tests: Program import
# ═══════════════════════════════════════════════════════════════════

class TestImportProgram:
    @patch("bbradar.modules.hackerone._api_request")
    def test_import_creates_project_and_targets(self, mock_api, tmp_db):
        mock_api.return_value = _mock_program_response()

        result = hackerone.import_program("testprog", db_path=tmp_db)

        assert result["project_id"] > 0
        assert result["targets_added"] == 3
        assert result["scope_rules_added"] == 3

        # Verify project
        proj = get_project(result["project_id"], db_path=tmp_db)
        assert proj["name"] == "Test Program"
        assert proj["platform"] == "hackerone"
        assert "hackerone.com/testprog" in proj["program_url"]

        # Verify targets
        tgts = list_targets(result["project_id"], db_path=tmp_db)
        values = {t["value"] for t in tgts}
        assert "*.example.com" in values
        assert "https://api.example.com" in values
        assert "admin.example.com" in values

        # Verify out-of-scope target
        admin_tgt = next(t for t in tgts if t["value"] == "admin.example.com")
        assert admin_tgt["in_scope"] == 0

    @patch("bbradar.modules.hackerone._api_request")
    def test_import_duplicate_rejected(self, mock_api, tmp_db):
        mock_api.return_value = _mock_program_response()

        hackerone.import_program("testprog", db_path=tmp_db)

        with pytest.raises(ValueError, match="already exists"):
            hackerone.import_program("testprog", db_path=tmp_db)

    @patch("bbradar.modules.hackerone._api_request")
    def test_import_scope_rules_created(self, mock_api, tmp_db):
        mock_api.return_value = _mock_program_response()

        result = hackerone.import_program("testprog", db_path=tmp_db)

        rules = list_rules(result["project_id"], db_path=tmp_db)
        assert len(rules) == 3


# ═══════════════════════════════════════════════════════════════════
# Tests: Scope sync
# ═══════════════════════════════════════════════════════════════════

class TestSyncScope:
    @patch("bbradar.modules.hackerone._api_request")
    def test_sync_adds_new_targets(self, mock_api, tmp_db):
        # First import
        mock_api.return_value = _mock_program_response()
        result = hackerone.import_program("testprog", db_path=tmp_db)
        pid = result["project_id"]

        # Now sync with updated scope that adds a new asset
        updated = _mock_program_response()
        updated["data"]["relationships"]["structured_scopes"]["data"].append({
            "attributes": {
                "asset_identifier": "staging.example.com",
                "asset_type": "DOMAIN",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "instruction": "",
                "max_severity": "high",
            }
        })
        mock_api.return_value = updated

        sync_result = hackerone.sync_scope(pid, "testprog", db_path=tmp_db)

        assert sync_result["new_targets"] == 1
        assert sync_result["new_rules"] == 1

    @patch("bbradar.modules.hackerone._api_request")
    def test_sync_no_duplicates(self, mock_api, tmp_db):
        mock_api.return_value = _mock_program_response()
        result = hackerone.import_program("testprog", db_path=tmp_db)
        pid = result["project_id"]

        # Sync again with same data — should add nothing
        sync_result = hackerone.sync_scope(pid, "testprog", db_path=tmp_db)
        assert sync_result["new_targets"] == 0
        assert sync_result["new_rules"] == 0


# ═══════════════════════════════════════════════════════════════════
# Tests: Program list and search
# ═══════════════════════════════════════════════════════════════════

class TestProgramDiscovery:
    @patch("bbradar.modules.hackerone._paginate")
    def test_list_programs(self, mock_paginate):
        mock_paginate.return_value = _mock_programs_list_response()["data"]

        progs = hackerone.list_programs()
        assert len(progs) == 2
        assert progs[0]["handle"] == "prog-a"
        assert progs[1]["name"] == "Program B"

    @patch("bbradar.modules.hackerone._paginate")
    def test_search_programs_filters(self, mock_paginate):
        mock_paginate.return_value = _mock_programs_list_response()["data"]

        results = hackerone.search_programs(query="Program A")
        assert len(results) == 1
        assert results[0]["handle"] == "prog-a"

    @patch("bbradar.modules.hackerone._paginate")
    def test_search_no_results(self, mock_paginate):
        mock_paginate.return_value = _mock_programs_list_response()["data"]

        results = hackerone.search_programs(query="nonexistent")
        assert len(results) == 0


# ═══════════════════════════════════════════════════════════════════
# Tests: Reports
# ═══════════════════════════════════════════════════════════════════

class TestReports:
    @patch("bbradar.modules.hackerone._paginate")
    def test_list_reports(self, mock_paginate):
        mock_paginate.return_value = _mock_reports_response()["data"]

        reports = hackerone.list_reports()
        assert len(reports) == 2
        assert reports[0]["title"] == "XSS on search"
        assert reports[0]["state"] == "resolved"
        assert reports[1]["state"] == "triaged"

    @patch("bbradar.modules.hackerone._api_request")
    def test_get_report(self, mock_api):
        mock_api.return_value = {
            "data": _mock_reports_response()["data"][0],
        }
        r = hackerone.get_report("100001")
        assert r["title"] == "XSS on search"
        assert r["state"] == "resolved"
        assert "100001" in r["url"]


# ═══════════════════════════════════════════════════════════════════
# Tests: Earnings
# ═══════════════════════════════════════════════════════════════════

class TestEarnings:
    @patch("bbradar.modules.hackerone._api_request")
    def test_get_balance(self, mock_api):
        mock_api.return_value = _mock_balance_response()

        bal = hackerone.get_balance()
        assert bal["balance"] == "1250.00"
        assert bal["currency"] == "USD"

    @patch("bbradar.modules.hackerone._paginate")
    def test_earnings_summary(self, mock_paginate):
        mock_paginate.return_value = _mock_earnings_response()["data"]

        summary = hackerone.get_earnings_summary()
        assert summary["total_earned"] == 1250.0
        assert summary["total_bounties"] == 2
        assert summary["average_bounty"] == 625.0
        assert "2025-03" in summary["by_month"]
        assert "2025-02" in summary["by_month"]


# ═══════════════════════════════════════════════════════════════════
# Tests: Dashboard
# ═══════════════════════════════════════════════════════════════════

class TestDashboard:
    @patch("bbradar.modules.hackerone.check_auth")
    def test_dashboard_without_h1(self, mock_auth, tmp_db):
        mock_auth.return_value = {"configured": False, "valid": False, "username": ""}

        data = hackerone.get_dashboard_data(db_path=tmp_db)

        assert "local" in data
        assert "hackerone" in data
        assert data["local"]["total_projects"] == 0
        assert data["hackerone"]["connected"] is False

    @patch("bbradar.modules.hackerone.check_auth")
    def test_dashboard_with_local_data(self, mock_auth, tmp_db):
        mock_auth.return_value = {"configured": False, "valid": False, "username": ""}

        # Create a project and vuln
        from bbradar.modules.projects import create_project
        pid = create_project("Test Prog", db_path=tmp_db)
        create_vuln(pid, "Test XSS", severity="high", db_path=tmp_db)

        data = hackerone.get_dashboard_data(db_path=tmp_db)

        assert data["local"]["total_projects"] == 1
        assert data["local"]["total_vulns"] == 1
        assert data["local"]["vulns_by_severity"].get("high") == 1


# ═══════════════════════════════════════════════════════════════════
# Tests: Credential validation
# ═══════════════════════════════════════════════════════════════════

class TestCredentials:
    def test_missing_credentials_raises(self):
        with patch("bbradar.modules.hackerone.load_config", return_value={"hackerone": {}}):
            with pytest.raises(ValueError, match="not configured"):
                hackerone._get_credentials()

    def test_empty_credentials_raises(self):
        with patch("bbradar.modules.hackerone.load_config",
                   return_value={"hackerone": {"username": "", "api_token": ""}}):
            with pytest.raises(ValueError, match="not configured"):
                hackerone._get_credentials()

    def test_valid_credentials_returned(self):
        with patch("bbradar.modules.hackerone.load_config",
                   return_value={"hackerone": {"username": "user", "api_token": "tok"}}):
            u, t = hackerone._get_credentials()
            assert u == "user"
            assert t == "tok"
