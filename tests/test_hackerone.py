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


def _mock_scope_data(response=None):
    """Extract scope data list from a mock program response (as _paginate returns)."""
    if response is None:
        response = _mock_program_response()
    return response["data"]["relationships"]["structured_scopes"]["data"]


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
    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_import_creates_project_and_targets(self, mock_api, mock_paginate, tmp_db):
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()

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

    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_import_duplicate_rejected(self, mock_api, mock_paginate, tmp_db):
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()

        hackerone.import_program("testprog", db_path=tmp_db)

        with pytest.raises(ValueError, match="already exists"):
            hackerone.import_program("testprog", db_path=tmp_db)

    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_import_scope_rules_created(self, mock_api, mock_paginate, tmp_db):
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()

        result = hackerone.import_program("testprog", db_path=tmp_db)

        rules = list_rules(result["project_id"], db_path=tmp_db)
        assert len(rules) == 3


# ═══════════════════════════════════════════════════════════════════
# Tests: Scope sync
# ═══════════════════════════════════════════════════════════════════

class TestSyncScope:
    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_sync_adds_new_targets(self, mock_api, mock_paginate, tmp_db):
        # First import
        resp = _mock_program_response()
        mock_api.return_value = resp
        mock_paginate.return_value = _mock_scope_data(resp)
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
        mock_paginate.return_value = _mock_scope_data(updated)

        sync_result = hackerone.sync_scope(pid, "testprog", db_path=tmp_db)

        assert sync_result["new_targets"] == 1
        assert sync_result["new_rules"] == 1

    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_sync_no_duplicates(self, mock_api, mock_paginate, tmp_db):
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()
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


# ═══════════════════════════════════════════════════════════════════
# Tests: Program Cache
# ═══════════════════════════════════════════════════════════════════

class TestProgramCache:
    @patch("bbradar.modules.hackerone._paginate")
    def test_refresh_populates_cache(self, mock_paginate, tmp_db):
        mock_paginate.return_value = _mock_programs_list_response()["data"]

        count = hackerone.refresh_program_cache(db_path=tmp_db)
        assert count == 2

        result = hackerone.get_cached_programs(db_path=tmp_db)
        assert result["total"] == 2
        assert result["filtered"] == 2
        assert result["from_cache"] is True

    @patch("bbradar.modules.hackerone._paginate")
    def test_bounties_filter(self, mock_paginate, tmp_db):
        mock_paginate.return_value = _mock_programs_list_response()["data"]
        hackerone.refresh_program_cache(db_path=tmp_db)

        result = hackerone.get_cached_programs(bounties_only=True, db_path=tmp_db)
        assert result["filtered"] == 1
        assert result["programs"][0]["handle"] == "prog-a"

    @patch("bbradar.modules.hackerone._paginate")
    def test_search_filter(self, mock_paginate, tmp_db):
        mock_paginate.return_value = _mock_programs_list_response()["data"]
        hackerone.refresh_program_cache(db_path=tmp_db)

        result = hackerone.get_cached_programs(search="Program B", db_path=tmp_db)
        assert result["filtered"] == 1
        assert result["programs"][0]["handle"] == "prog-b"

    @patch("bbradar.modules.hackerone._paginate")
    def test_search_by_handle(self, mock_paginate, tmp_db):
        mock_paginate.return_value = _mock_programs_list_response()["data"]
        hackerone.refresh_program_cache(db_path=tmp_db)

        result = hackerone.get_cached_programs(search="prog-a", db_path=tmp_db)
        assert result["filtered"] == 1

    @patch("bbradar.modules.hackerone._paginate")
    def test_sort_newest(self, mock_paginate, tmp_db):
        mock_paginate.return_value = _mock_programs_list_response()["data"]
        hackerone.refresh_program_cache(db_path=tmp_db)

        result = hackerone.get_cached_programs(sort="newest", db_path=tmp_db)
        # prog-b started 2024-06, prog-a started 2024-01
        assert result["programs"][0]["handle"] == "prog-b"

    @patch("bbradar.modules.hackerone._paginate")
    def test_state_filter(self, mock_paginate, tmp_db):
        mock_paginate.return_value = _mock_programs_list_response()["data"]
        hackerone.refresh_program_cache(db_path=tmp_db)

        result = hackerone.get_cached_programs(state="public_mode", db_path=tmp_db)
        assert result["filtered"] == 2

        result = hackerone.get_cached_programs(state="nonexistent", db_path=tmp_db)
        assert result["filtered"] == 0

    @patch("bbradar.modules.hackerone._paginate")
    def test_auto_refresh_when_stale(self, mock_paginate, tmp_db):
        """First call should auto-refresh from API since cache is empty."""
        mock_paginate.return_value = _mock_programs_list_response()["data"]

        result = hackerone.get_cached_programs(db_path=tmp_db)
        assert result["from_cache"] is False
        assert result["total"] == 2

    @patch("bbradar.modules.hackerone._paginate")
    def test_force_refresh(self, mock_paginate, tmp_db):
        mock_paginate.return_value = _mock_programs_list_response()["data"]
        hackerone.refresh_program_cache(db_path=tmp_db)

        result = hackerone.get_cached_programs(refresh=True, db_path=tmp_db)
        assert result["from_cache"] is False

    @patch("bbradar.modules.hackerone._paginate")
    def test_combined_filters(self, mock_paginate, tmp_db):
        mock_paginate.return_value = _mock_programs_list_response()["data"]
        hackerone.refresh_program_cache(db_path=tmp_db)

        # Bounties + search — only prog-a pays bounties and matches
        result = hackerone.get_cached_programs(
            bounties_only=True, search="prog", db_path=tmp_db
        )
        assert result["filtered"] == 1
        assert result["programs"][0]["handle"] == "prog-a"


# ═══════════════════════════════════════════════════════════════════
# Tests: Scope Watch
# ═══════════════════════════════════════════════════════════════════

class TestWatchProgram:
    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_watch_creates_entry_and_snapshot(self, mock_api, mock_paginate, tmp_db):
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()

        result = hackerone.watch_program("testprog", db_path=tmp_db)

        assert result["handle"] == "testprog"
        assert result["name"] == "Test Program"
        assert result["scopes_snapshotted"] == 3
        assert result["project_id"] is None  # no project linked

        # Verify watchlist
        watched = hackerone.list_watched(db_path=tmp_db)
        assert len(watched) == 1
        assert watched[0]["handle"] == "testprog"
        assert watched[0]["scope_count"] == 3

    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_watch_links_existing_project(self, mock_api, mock_paginate, tmp_db):
        """If a project was imported from this handle, it should auto-link."""
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()
        imp = hackerone.import_program("testprog", db_path=tmp_db)

        result = hackerone.watch_program("testprog", db_path=tmp_db)
        assert result["project_id"] == imp["project_id"]

    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_watch_idempotent(self, mock_api, mock_paginate, tmp_db):
        """Watching twice should update, not fail."""
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()

        hackerone.watch_program("testprog", db_path=tmp_db)
        result = hackerone.watch_program("testprog", db_path=tmp_db)
        assert result["scopes_snapshotted"] == 3
        assert len(hackerone.list_watched(db_path=tmp_db)) == 1


class TestUnwatchProgram:
    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_unwatch_removes_entry(self, mock_api, mock_paginate, tmp_db):
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()

        hackerone.watch_program("testprog", db_path=tmp_db)
        assert len(hackerone.list_watched(db_path=tmp_db)) == 1

        hackerone.unwatch_program("testprog", db_path=tmp_db)
        assert len(hackerone.list_watched(db_path=tmp_db)) == 0


class TestCheckProgram:
    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_no_changes(self, mock_api, mock_paginate, tmp_db):
        """Same scope on check should show no changes."""
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()
        hackerone.watch_program("testprog", db_path=tmp_db)

        result = hackerone.check_program("testprog", db_path=tmp_db)
        assert result["has_changes"] is False
        assert result["new"] == []
        assert result["removed"] == []
        assert result["changed"] == []

    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_new_asset_detected(self, mock_api, mock_paginate, tmp_db):
        """Adding a new asset should show up as 'new'."""
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()
        hackerone.watch_program("testprog", db_path=tmp_db)

        # Now add a new scope asset
        updated = _mock_program_response()
        updated["data"]["relationships"]["structured_scopes"]["data"].append({
            "attributes": {
                "asset_identifier": "staging.example.com",
                "asset_type": "DOMAIN",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "instruction": "New staging",
                "max_severity": "critical",
            }
        })
        mock_api.return_value = updated
        mock_paginate.return_value = _mock_scope_data(updated)

        result = hackerone.check_program("testprog", db_path=tmp_db)
        assert result["has_changes"] is True
        assert len(result["new"]) == 1
        assert result["new"][0]["asset_identifier"] == "staging.example.com"
        assert result["removed"] == []

    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_removed_asset_detected(self, mock_api, mock_paginate, tmp_db):
        """Removing an asset should show up as 'removed'."""
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()
        hackerone.watch_program("testprog", db_path=tmp_db)

        # Remove the last scope entry
        shrunk = _mock_program_response()
        shrunk["data"]["relationships"]["structured_scopes"]["data"] = \
            shrunk["data"]["relationships"]["structured_scopes"]["data"][:2]
        mock_api.return_value = shrunk
        mock_paginate.return_value = _mock_scope_data(shrunk)

        result = hackerone.check_program("testprog", db_path=tmp_db)
        assert result["has_changes"] is True
        assert len(result["removed"]) == 1
        assert result["removed"][0]["asset_identifier"] == "admin.example.com"

    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_changed_asset_detected(self, mock_api, mock_paginate, tmp_db):
        """Changing bounty eligibility should show up as 'changed'."""
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()
        hackerone.watch_program("testprog", db_path=tmp_db)

        # Change admin.example.com to become bounty-eligible
        modified = _mock_program_response()
        modified["data"]["relationships"]["structured_scopes"]["data"][2]["attributes"]["eligible_for_bounty"] = True
        modified["data"]["relationships"]["structured_scopes"]["data"][2]["attributes"]["eligible_for_submission"] = True
        mock_api.return_value = modified
        mock_paginate.return_value = _mock_scope_data(modified)

        result = hackerone.check_program("testprog", db_path=tmp_db)
        assert result["has_changes"] is True
        assert len(result["changed"]) == 1
        assert result["changed"][0]["asset_identifier"] == "admin.example.com"
        assert "eligible_for_bounty" in result["changed"][0]["changes"]

    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_auto_import_new_scope(self, mock_api, mock_paginate, tmp_db):
        """auto_import should add new assets to linked project."""
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()
        imp = hackerone.import_program("testprog", db_path=tmp_db)
        hackerone.watch_program("testprog", db_path=tmp_db)

        # Add a new scope to program
        updated = _mock_program_response()
        updated["data"]["relationships"]["structured_scopes"]["data"].append({
            "attributes": {
                "asset_identifier": "new.example.com",
                "asset_type": "DOMAIN",
                "eligible_for_bounty": True,
                "eligible_for_submission": True,
                "instruction": "",
                "max_severity": "high",
            }
        })
        mock_api.return_value = updated
        mock_paginate.return_value = _mock_scope_data(updated)

        result = hackerone.check_program("testprog", auto_import=True, db_path=tmp_db)
        assert result["auto_imported"] >= 1

        # Verify the target was added to the project
        tgts = list_targets(imp["project_id"], db_path=tmp_db)
        values = {t["value"] for t in tgts}
        assert "new.example.com" in values


class TestCheckAllWatched:
    @patch("bbradar.modules.hackerone._paginate")
    @patch("bbradar.modules.hackerone._api_request")
    def test_check_all_returns_list(self, mock_api, mock_paginate, tmp_db):
        mock_api.return_value = _mock_program_response()
        mock_paginate.return_value = _mock_scope_data()
        hackerone.watch_program("testprog", db_path=tmp_db)

        results = hackerone.check_all_watched(db_path=tmp_db)
        assert len(results) == 1
        assert results[0]["handle"] == "testprog"


class TestCheckNewPrograms:
    @patch("bbradar.modules.hackerone._paginate")
    def test_filters_known_programs(self, mock_paginate, tmp_db):
        mock_paginate.return_value = _mock_programs_list_response()["data"]

        # Watch one of the programs so it's "known"
        from bbradar.core.database import get_connection
        with get_connection(tmp_db) as conn:
            conn.execute(
                "INSERT INTO h1_watched_programs (handle, name) VALUES (?, ?)",
                ("prog-a", "Program A"),
            )

        new = hackerone.check_new_programs(db_path=tmp_db)
        handles = [p["handle"] for p in new]
        assert "prog-a" not in handles
        assert "prog-b" in handles


# ═══════════════════════════════════════════════════════════════════
# Mock data: Hacktivity & Weaknesses
# ═══════════════════════════════════════════════════════════════════

def _mock_hacktivity_response(handle="testprog", count=3):
    """Build a mock hacktivity API response."""
    items = []
    for i in range(count):
        sev = ["critical", "high", "medium"][i % 3]
        items.append({
            "id": str(9000 + i),
            "attributes": {
                "title": f"Bug #{i} in {handle}",
                "severity_rating": sev,
                "cwe": f"CWE-{79 + i}",
                "cve_ids": [f"CVE-2025-{1000 + i}"],
                "total_awarded_amount": 500.0 * (i + 1),
                "substate": "resolved",
                "url": f"https://hackerone.com/reports/{9000 + i}",
                "disclosed_at": f"2025-0{i + 1}-15T10:00:00Z",
                "submitted_at": f"2025-0{i + 1}-01T10:00:00Z",
                "votes": i + 1,
            },
            "relationships": {
                "reporter": {
                    "data": {
                        "attributes": {
                            "username": f"hacker{i}",
                        }
                    }
                }
            },
        })
    return {"data": items, "links": {}}


def _mock_weaknesses_response():
    """Build mock weakness items as returned by _paginate."""
    return [
        {
            "id": "w1",
            "attributes": {
                "name": "Cross-Site Scripting (XSS)",
                "description": "Reflected XSS",
                "external_id": "cwe-79",
            },
        },
        {
            "id": "w2",
            "attributes": {
                "name": "SQL Injection",
                "description": "SQL injection via user input",
                "external_id": "cwe-89",
            },
        },
        {
            "id": "w3",
            "attributes": {
                "name": "IDOR",
                "description": "Insecure direct object references",
                "external_id": "cwe-639",
            },
        },
    ]


# ═══════════════════════════════════════════════════════════════════
# Tests: get_hacktivity
# ═══════════════════════════════════════════════════════════════════

class TestGetHacktivity:
    @patch("bbradar.modules.hackerone._api_request")
    def test_basic_fetch(self, mock_api):
        resp = _mock_hacktivity_response()
        mock_api.return_value = resp

        reports = hackerone.get_hacktivity("testprog")
        assert len(reports) == 3
        assert reports[0]["id"] == "9000"
        assert reports[0]["title"] == "Bug #0 in testprog"
        assert reports[0]["severity_rating"] == "critical"
        assert reports[0]["reporter_username"] == "hacker0"

        # Verify Lucene query syntax
        call_args = mock_api.call_args
        assert call_args[0][0] == "hacktivity"
        assert call_args[0][1]["queryString"] == "team:testprog"

    @patch("bbradar.modules.hackerone._api_request")
    def test_empty_hacktivity(self, mock_api):
        mock_api.return_value = {"data": [], "links": {}}
        reports = hackerone.get_hacktivity("empty-prog")
        assert reports == []

    @patch("bbradar.modules.hackerone._api_request")
    def test_pagination(self, mock_api):
        """Follows pagination when next link present."""
        page1 = _mock_hacktivity_response(count=2)
        page1["links"] = {"next": "https://api.hackerone.com/v1/hackers/hacktivity?page=2"}
        page2 = _mock_hacktivity_response(count=1)
        page2["data"][0]["id"] = "9999"
        page2["links"] = {}

        mock_api.side_effect = [page1, page2]
        reports = hackerone.get_hacktivity("testprog", max_pages=5)
        assert len(reports) == 3
        assert mock_api.call_count == 2

    @patch("bbradar.modules.hackerone._api_request")
    def test_max_pages_limit(self, mock_api):
        """Stops at max_pages even if more data available."""
        page = _mock_hacktivity_response(count=1)
        page["links"] = {"next": "https://api.hackerone.com/v1/hackers/hacktivity?page=2"}
        mock_api.return_value = page

        reports = hackerone.get_hacktivity("testprog", max_pages=1)
        assert len(reports) == 1
        assert mock_api.call_count == 1

    @patch("bbradar.modules.hackerone._api_request")
    def test_extracts_cve_ids(self, mock_api):
        mock_api.return_value = _mock_hacktivity_response(count=1)
        reports = hackerone.get_hacktivity("testprog")
        assert reports[0]["cve_ids"] == ["CVE-2025-1000"]


# ═══════════════════════════════════════════════════════════════════
# Tests: get_weaknesses
# ═══════════════════════════════════════════════════════════════════

class TestGetWeaknesses:
    @patch("bbradar.modules.hackerone._paginate")
    def test_basic_fetch(self, mock_paginate):
        mock_paginate.return_value = _mock_weaknesses_response()
        weaknesses = hackerone.get_weaknesses("testprog")

        assert len(weaknesses) == 3
        assert weaknesses[0]["name"] == "Cross-Site Scripting (XSS)"
        assert weaknesses[0]["external_id"] == "cwe-79"
        assert weaknesses[1]["name"] == "SQL Injection"
        mock_paginate.assert_called_once_with("programs/testprog/weaknesses")

    @patch("bbradar.modules.hackerone._paginate")
    def test_empty(self, mock_paginate):
        mock_paginate.return_value = []
        weaknesses = hackerone.get_weaknesses("empty-prog")
        assert weaknesses == []


# ═══════════════════════════════════════════════════════════════════
# Tests: Intel caching
# ═══════════════════════════════════════════════════════════════════

class TestIntelCaching:
    def test_cache_and_retrieve_hacktivity(self, tmp_db):
        reports = [
            {"id": "9000", "title": "XSS", "severity_rating": "high",
             "cwe": "CWE-79", "cve_ids": ["CVE-2025-1000"],
             "total_awarded_amount": 500.0, "substate": "resolved",
             "url": "https://hackerone.com/reports/9000",
             "reporter_username": "hacker0",
             "disclosed_at": "2025-01-15T10:00:00Z",
             "submitted_at": "2025-01-01T10:00:00Z"},
            {"id": "9001", "title": "SQLi", "severity_rating": "critical",
             "cwe": "CWE-89", "cve_ids": [],
             "total_awarded_amount": 1000.0, "substate": "resolved",
             "url": "", "reporter_username": "hacker1",
             "disclosed_at": "2025-02-15T10:00:00Z",
             "submitted_at": "2025-02-01T10:00:00Z"},
        ]
        hackerone.cache_hacktivity("testprog", reports, db_path=tmp_db)

        cached = hackerone.get_cached_hacktivity("testprog", db_path=tmp_db)
        assert len(cached) == 2
        # Should be ordered by disclosed_at DESC
        assert cached[0]["title"] == "SQLi"
        assert cached[1]["title"] == "XSS"

    def test_cache_and_retrieve_weaknesses(self, tmp_db):
        weaknesses = [
            {"id": "w1", "name": "XSS", "description": "Reflected XSS",
             "external_id": "cwe-79"},
            {"id": "w2", "name": "SQLi", "description": "",
             "external_id": "cwe-89"},
        ]
        hackerone.cache_weaknesses("testprog", weaknesses, db_path=tmp_db)

        cached = hackerone.get_cached_weaknesses("testprog", db_path=tmp_db)
        assert len(cached) == 2
        # Should be ordered by name
        assert cached[0]["name"] == "SQLi"
        assert cached[1]["name"] == "XSS"

    def test_cache_freshness(self, tmp_db):
        reports = [
            {"id": "9000", "title": "XSS", "severity_rating": "high",
             "cwe": "", "cve_ids": [], "total_awarded_amount": None,
             "substate": "resolved", "url": "", "reporter_username": "",
             "disclosed_at": "", "submitted_at": ""},
        ]
        hackerone.cache_hacktivity("testprog", reports, db_path=tmp_db)
        assert hackerone._intel_cache_fresh("testprog", "h1_hacktivity_cache", db_path=tmp_db)
        assert not hackerone._intel_cache_fresh("other-prog", "h1_hacktivity_cache", db_path=tmp_db)

    def test_cache_replaces_old_data(self, tmp_db):
        """Caching again replaces previous data for the same handle."""
        reports_v1 = [
            {"id": "9000", "title": "Old Bug", "severity_rating": "low",
             "cwe": "", "cve_ids": [], "total_awarded_amount": None,
             "substate": "resolved", "url": "", "reporter_username": "",
             "disclosed_at": "", "submitted_at": ""},
        ]
        reports_v2 = [
            {"id": "9001", "title": "New Bug", "severity_rating": "high",
             "cwe": "", "cve_ids": [], "total_awarded_amount": None,
             "substate": "resolved", "url": "", "reporter_username": "",
             "disclosed_at": "", "submitted_at": ""},
        ]
        hackerone.cache_hacktivity("testprog", reports_v1, db_path=tmp_db)
        hackerone.cache_hacktivity("testprog", reports_v2, db_path=tmp_db)

        cached = hackerone.get_cached_hacktivity("testprog", db_path=tmp_db)
        assert len(cached) == 1
        assert cached[0]["title"] == "New Bug"

    def test_separate_handle_caches(self, tmp_db):
        """Different handles have separate caches."""
        r1 = [{"id": "1", "title": "Bug A", "severity_rating": "high",
               "cwe": "", "cve_ids": [], "total_awarded_amount": None,
               "substate": "", "url": "", "reporter_username": "",
               "disclosed_at": "", "submitted_at": ""}]
        r2 = [{"id": "2", "title": "Bug B", "severity_rating": "low",
               "cwe": "", "cve_ids": [], "total_awarded_amount": None,
               "substate": "", "url": "", "reporter_username": "",
               "disclosed_at": "", "submitted_at": ""}]
        hackerone.cache_hacktivity("prog-a", r1, db_path=tmp_db)
        hackerone.cache_hacktivity("prog-b", r2, db_path=tmp_db)

        assert len(hackerone.get_cached_hacktivity("prog-a", db_path=tmp_db)) == 1
        assert len(hackerone.get_cached_hacktivity("prog-b", db_path=tmp_db)) == 1
        assert hackerone.get_cached_hacktivity("prog-a", db_path=tmp_db)[0]["title"] == "Bug A"


# ═══════════════════════════════════════════════════════════════════
# Tests: get_program_intel
# ═══════════════════════════════════════════════════════════════════

class TestGetProgramIntel:
    @patch("bbradar.modules.hackerone.get_weaknesses")
    @patch("bbradar.modules.hackerone.get_hacktivity")
    @patch("bbradar.modules.hackerone.get_program")
    def test_full_intel(self, mock_prog, mock_hacktivity, mock_weaknesses, tmp_db):
        mock_prog.return_value = {
            "handle": "testprog", "name": "Test Program",
            "offers_bounties": True,
        }
        mock_hacktivity.return_value = [
            {"id": "1", "title": "XSS", "severity_rating": "high",
             "cwe": "CWE-79", "cve_ids": [], "total_awarded_amount": 500.0,
             "substate": "resolved", "url": "", "reporter_username": "alice",
             "disclosed_at": "2025-01-15", "submitted_at": "2025-01-01"},
            {"id": "2", "title": "SQLi", "severity_rating": "critical",
             "cwe": "CWE-89", "cve_ids": [], "total_awarded_amount": 2000.0,
             "substate": "resolved", "url": "", "reporter_username": "bob",
             "disclosed_at": "2025-02-15", "submitted_at": "2025-02-01"},
            {"id": "3", "title": "CSRF", "severity_rating": "medium",
             "cwe": "CWE-352", "cve_ids": [], "total_awarded_amount": None,
             "substate": "resolved", "url": "", "reporter_username": "alice",
             "disclosed_at": "2025-03-15", "submitted_at": "2025-03-01"},
        ]
        mock_weaknesses.return_value = [
            {"id": "w1", "name": "XSS", "description": "", "external_id": "cwe-79"},
        ]

        intel = hackerone.get_program_intel("testprog", refresh=True, db_path=tmp_db)

        assert intel["handle"] == "testprog"
        assert intel["name"] == "Test Program"
        assert intel["offers_bounties"] is True
        assert len(intel["hacktivity"]) == 3
        assert len(intel["weaknesses"]) == 1

        stats = intel["stats"]
        assert stats["total_disclosed"] == 3
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["medium"] == 1
        assert stats["bounty_min"] == 500.0
        assert stats["bounty_max"] == 2000.0
        assert stats["bounty_avg"] == 1250.0
        assert stats["bounty_total"] == 2500.0
        assert stats["bounty_count"] == 2

        # Top reporters
        reporter_names = [r[0] for r in stats["top_reporters"]]
        assert "alice" in reporter_names
        assert "bob" in reporter_names

        # Top CWEs
        cwe_names = [c[0] for c in stats["top_cwes"]]
        assert "CWE-79" in cwe_names

    @patch("bbradar.modules.hackerone.get_weaknesses")
    @patch("bbradar.modules.hackerone.get_hacktivity")
    @patch("bbradar.modules.hackerone.get_program")
    def test_uses_cache_when_fresh(self, mock_prog, mock_hacktivity, mock_weaknesses, tmp_db):
        """Should use cached data when available and not refreshing."""
        mock_prog.return_value = {
            "handle": "testprog", "name": "Test Program",
            "offers_bounties": True,
        }
        # Seed cache
        reports = [
            {"id": "1", "title": "Cached Bug", "severity_rating": "low",
             "cwe": "", "cve_ids": [], "total_awarded_amount": None,
             "substate": "resolved", "url": "", "reporter_username": "",
             "disclosed_at": "", "submitted_at": ""},
        ]
        hackerone.cache_hacktivity("testprog", reports, db_path=tmp_db)
        hackerone.cache_weaknesses("testprog", [
            {"id": "w1", "name": "XSS", "description": "", "external_id": "cwe-79"},
        ], db_path=tmp_db)

        intel = hackerone.get_program_intel("testprog", refresh=False, db_path=tmp_db)
        # API should NOT be called for hacktivity/weaknesses
        mock_hacktivity.assert_not_called()
        mock_weaknesses.assert_not_called()
        assert intel["stats"]["total_disclosed"] == 1

    @patch("bbradar.modules.hackerone.get_weaknesses")
    @patch("bbradar.modules.hackerone.get_hacktivity")
    @patch("bbradar.modules.hackerone.get_program")
    def test_no_bounties(self, mock_prog, mock_hacktivity, mock_weaknesses, tmp_db):
        """Stats with no paid bounties."""
        mock_prog.return_value = {
            "handle": "testprog", "name": "Test",
            "offers_bounties": False,
        }
        mock_hacktivity.return_value = [
            {"id": "1", "title": "Bug", "severity_rating": "low",
             "cwe": "", "cve_ids": [], "total_awarded_amount": None,
             "substate": "resolved", "url": "", "reporter_username": "",
             "disclosed_at": "", "submitted_at": ""},
        ]
        mock_weaknesses.return_value = []

        intel = hackerone.get_program_intel("testprog", refresh=True, db_path=tmp_db)
        assert intel["stats"]["bounty_count"] == 0
        assert intel["stats"]["bounty_min"] == 0
        assert intel["stats"]["bounty_max"] == 0
        assert intel["stats"]["bounty_avg"] == 0


# ═══════════════════════════════════════════════════════════════════
# Tests: check_new_hacktivity
# ═══════════════════════════════════════════════════════════════════

class TestCheckNewHacktivity:
    @patch("bbradar.modules.hackerone.get_hacktivity")
    def test_detects_new_disclosures(self, mock_hacktivity, tmp_db):
        """Detects newly disclosed reports vs cached data."""
        from bbradar.core.database import get_connection

        # Set up a watched program
        with get_connection(tmp_db) as conn:
            conn.execute(
                "INSERT INTO h1_watched_programs (handle, name) VALUES (?, ?)",
                ("testprog", "Test Program"),
            )

        # Seed cache with one known report
        hackerone.cache_hacktivity("testprog", [
            {"id": "9000", "title": "Known Bug", "severity_rating": "high",
             "cwe": "", "cve_ids": [], "total_awarded_amount": None,
             "substate": "resolved", "url": "", "reporter_username": "",
             "disclosed_at": "", "submitted_at": ""},
        ], db_path=tmp_db)

        # API returns the known report + a new one
        mock_hacktivity.return_value = [
            {"id": "9000", "title": "Known Bug", "severity_rating": "high",
             "cwe": "", "cve_ids": [], "total_awarded_amount": None,
             "substate": "resolved", "url": "", "reporter_username": "",
             "disclosed_at": "", "submitted_at": ""},
            {"id": "9001", "title": "New Bug", "severity_rating": "critical",
             "cwe": "CWE-79", "cve_ids": [], "total_awarded_amount": 1000.0,
             "substate": "resolved", "url": "", "reporter_username": "finder",
             "disclosed_at": "2025-04-01", "submitted_at": "2025-03-01"},
        ]

        results = hackerone.check_new_hacktivity(db_path=tmp_db)
        assert len(results) == 1
        assert results[0]["handle"] == "testprog"
        assert len(results[0]["new_reports"]) == 1
        assert results[0]["new_reports"][0]["id"] == "9001"

    @patch("bbradar.modules.hackerone.get_hacktivity")
    def test_no_new_disclosures(self, mock_hacktivity, tmp_db):
        """Returns empty when no new disclosures found."""
        from bbradar.core.database import get_connection

        with get_connection(tmp_db) as conn:
            conn.execute(
                "INSERT INTO h1_watched_programs (handle, name) VALUES (?, ?)",
                ("testprog", "Test Program"),
            )

        hackerone.cache_hacktivity("testprog", [
            {"id": "9000", "title": "Known Bug", "severity_rating": "high",
             "cwe": "", "cve_ids": [], "total_awarded_amount": None,
             "substate": "resolved", "url": "", "reporter_username": "",
             "disclosed_at": "", "submitted_at": ""},
        ], db_path=tmp_db)

        # Same data as cache
        mock_hacktivity.return_value = [
            {"id": "9000", "title": "Known Bug", "severity_rating": "high",
             "cwe": "", "cve_ids": [], "total_awarded_amount": None,
             "substate": "resolved", "url": "", "reporter_username": "",
             "disclosed_at": "", "submitted_at": ""},
        ]

        results = hackerone.check_new_hacktivity(db_path=tmp_db)
        assert results == []

    @patch("bbradar.modules.hackerone.get_hacktivity")
    def test_api_error_skips_program(self, mock_hacktivity, tmp_db):
        """API errors for a program should be skipped gracefully."""
        from bbradar.core.database import get_connection

        with get_connection(tmp_db) as conn:
            conn.execute(
                "INSERT INTO h1_watched_programs (handle, name) VALUES (?, ?)",
                ("testprog", "Test Program"),
            )

        mock_hacktivity.side_effect = Exception("API error")

        results = hackerone.check_new_hacktivity(db_path=tmp_db)
        assert results == []

    @patch("bbradar.modules.hackerone.get_hacktivity")
    def test_empty_cache_all_new(self, mock_hacktivity, tmp_db):
        """With empty cache, all reports are counted as new."""
        from bbradar.core.database import get_connection

        with get_connection(tmp_db) as conn:
            conn.execute(
                "INSERT INTO h1_watched_programs (handle, name) VALUES (?, ?)",
                ("testprog", "Test Program"),
            )

        mock_hacktivity.return_value = [
            {"id": "9000", "title": "Bug A", "severity_rating": "high",
             "cwe": "", "cve_ids": [], "total_awarded_amount": None,
             "substate": "resolved", "url": "", "reporter_username": "",
             "disclosed_at": "", "submitted_at": ""},
            {"id": "9001", "title": "Bug B", "severity_rating": "medium",
             "cwe": "", "cve_ids": [], "total_awarded_amount": None,
             "substate": "resolved", "url": "", "reporter_username": "",
             "disclosed_at": "", "submitted_at": ""},
        ]

        results = hackerone.check_new_hacktivity(db_path=tmp_db)
        assert len(results) == 1
        assert len(results[0]["new_reports"]) == 2
