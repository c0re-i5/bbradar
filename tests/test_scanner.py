"""
Tests for scanner integration module.

Tests cover:
  - Scanner config loading
  - ZAP client API methods (mocked)
  - Burp client API methods (mocked)
  - Alert/issue import and dedup
  - Scope sync
  - Spider integration
  - Monitor loop
  - Workflow scanner steps
  - DB migration #7 (new vuln columns)
  - Probe scanner suggestions
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from bbradar.modules.projects import create_project
from bbradar.modules.targets import add_target
from bbradar.modules.vulns import create_vuln, get_vuln, list_vulns, VALID_VULN_TYPES
from bbradar.modules.scope import add_rule
from bbradar.modules.probe import get_target_intel, suggest_actions
from bbradar.modules.recon import list_recon, add_recon


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture
def project(tmp_db):
    pid = create_project("ScannerTest", db_path=tmp_db)
    return pid, tmp_db


@pytest.fixture
def target(project):
    pid, db = project
    tid = add_target(pid, "domain", "example.com", db_path=db)
    return tid, pid, db


@pytest.fixture
def mock_requests():
    """Patch requests library for scanner module."""
    with patch("bbradar.modules.scanner._require_requests") as mock:
        requests_mock = MagicMock()
        mock.return_value = requests_mock
        yield requests_mock


# ══════════════════════════════════════════════════════════════
# DB Migration #7 — new vuln columns
# ══════════════════════════════════════════════════════════════

class TestMigration7:
    def test_new_columns_exist_in_fresh_db(self, project):
        pid, db = project
        vid = create_vuln(
            pid, "Test XSS", severity="high", vuln_type="xss",
            source_tool="zap", confidence="certain",
            cwe_id="CWE-79", cve_id="CVE-2024-1234",
            owasp_category="A03:2021",
            db_path=db,
        )
        vuln = get_vuln(vid, db)
        assert vuln["source_tool"] == "zap"
        assert vuln["confidence"] == "certain"
        assert vuln["cwe_id"] == "CWE-79"
        assert vuln["cve_id"] == "CVE-2024-1234"
        assert vuln["owasp_category"] == "A03:2021"

    def test_new_columns_nullable(self, project):
        pid, db = project
        vid = create_vuln(pid, "Simple Finding", db_path=db)
        vuln = get_vuln(vid, db)
        assert vuln["source_tool"] is None
        assert vuln["confidence"] is None
        assert vuln["cwe_id"] is None

    def test_ingest_passes_new_fields(self, project):
        """Verify _create_draft_vuln now passes source_tool/confidence/cwe_id."""
        pid, db = project
        from bbradar.modules.ingest import _create_draft_vuln
        finding = {
            "title": "SQL Injection via id param",
            "severity": "high",
            "vuln_type": "sqli",
            "description": "Found via automated scan",
            "tool": "zap",
            "confidence": "firm",
            "cwe_id": "CWE-89",
            "cve_id": "CVE-2024-5678",
        }
        vid = _create_draft_vuln(finding, pid, db_path=db)
        vuln = get_vuln(vid, db)
        assert vuln["source_tool"] == "zap"
        assert vuln["confidence"] == "firm"
        assert vuln["cwe_id"] == "CWE-89"
        assert vuln["cve_id"] == "CVE-2024-5678"


# ══════════════════════════════════════════════════════════════
# Scanner Config
# ══════════════════════════════════════════════════════════════

class TestScannerConfig:
    def test_default_zap_config(self):
        from bbradar.modules.scanner import _get_scanner_config
        cfg = _get_scanner_config("zap")
        assert "localhost" in cfg["url"]
        assert "8080" in cfg["url"]

    def test_default_burp_config(self):
        from bbradar.modules.scanner import _get_scanner_config
        cfg = _get_scanner_config("burp")
        assert "localhost" in cfg["url"]
        assert "1337" in cfg["url"]

    def test_invalid_scanner_type(self):
        from bbradar.modules.scanner import _get_scanner_config
        with pytest.raises(ValueError, match="Unknown scanner"):
            _get_scanner_config("nessus")


# ══════════════════════════════════════════════════════════════
# ZAP Client
# ══════════════════════════════════════════════════════════════

class TestZAPClient:
    def test_version(self, mock_requests):
        from bbradar.modules.scanner import ZAPClient
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"version": "2.15.0"}
        mock_requests.get.return_value = resp

        zap = ZAPClient(url="http://localhost:8080")
        assert zap.version() == "2.15.0"

    def test_urls(self, mock_requests):
        from bbradar.modules.scanner import ZAPClient
        resp = MagicMock()
        resp.json.return_value = {"urls": ["https://example.com/", "https://example.com/admin"]}
        mock_requests.get.return_value = resp

        zap = ZAPClient(url="http://localhost:8080")
        urls = zap.urls()
        assert len(urls) == 2
        assert "https://example.com/admin" in urls

    def test_alerts(self, mock_requests):
        from bbradar.modules.scanner import ZAPClient
        resp = MagicMock()
        resp.json.return_value = {"alerts": [
            {"name": "XSS", "risk": "3", "url": "https://example.com/search"},
            {"name": "Info Leak", "risk": "1", "url": "https://example.com/"},
        ]}
        mock_requests.get.return_value = resp

        zap = ZAPClient(url="http://localhost:8080")
        alerts = zap.alerts()
        assert len(alerts) == 2

    def test_spider_scan(self, mock_requests):
        from bbradar.modules.scanner import ZAPClient
        resp = MagicMock()
        resp.json.return_value = {"scan": "42"}
        mock_requests.get.return_value = resp

        zap = ZAPClient(url="http://localhost:8080")
        scan_id = zap.spider_scan("https://example.com")
        assert scan_id == "42"

    def test_active_scan(self, mock_requests):
        from bbradar.modules.scanner import ZAPClient
        resp = MagicMock()
        resp.json.return_value = {"scan": "99"}
        mock_requests.get.return_value = resp

        zap = ZAPClient(url="http://localhost:8080")
        scan_id = zap.active_scan("https://example.com")
        assert scan_id == "99"

    def test_context_operations(self, mock_requests):
        from bbradar.modules.scanner import ZAPClient
        resp = MagicMock()
        resp.json.return_value = {"contextId": "1"}
        mock_requests.get.return_value = resp

        zap = ZAPClient(url="http://localhost:8080")
        ctx_id = zap.new_context("test-ctx")
        assert ctx_id == "1"
        # These should not raise
        zap.include_in_context("test-ctx", ".*example\\.com.*")
        zap.exclude_from_context("test-ctx", ".*logout.*")

    def test_api_key_included(self, mock_requests):
        from bbradar.modules.scanner import ZAPClient
        resp = MagicMock()
        resp.json.return_value = {"version": "2.15.0"}
        mock_requests.get.return_value = resp

        zap = ZAPClient(url="http://localhost:8080", api_key="secret123")
        zap.version()
        call_kwargs = mock_requests.get.call_args
        assert "apikey" in call_kwargs.kwargs.get("params", {})


# ══════════════════════════════════════════════════════════════
# Burp Client
# ══════════════════════════════════════════════════════════════

class TestBurpClient:
    def test_scan_launch(self, mock_requests):
        from bbradar.modules.scanner import BurpClient
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b'{"task_id": "abc123"}'
        resp.json.return_value = {"task_id": "abc123"}
        mock_requests.post.return_value = resp

        burp = BurpClient(url="http://localhost:1337")
        task_id = burp.scan(["https://example.com"])
        assert task_id == "abc123"

    def test_scan_status(self, mock_requests):
        from bbradar.modules.scanner import BurpClient
        resp = MagicMock()
        resp.content = b'{"scan_status": "succeeded"}'
        resp.json.return_value = {"scan_status": "succeeded", "issue_events": []}
        mock_requests.get.return_value = resp

        burp = BurpClient(url="http://localhost:1337")
        status = burp.scan_status("abc123")
        assert status["scan_status"] == "succeeded"


# ══════════════════════════════════════════════════════════════
# Status Check
# ══════════════════════════════════════════════════════════════

class TestStatusCheck:
    def test_check_status_zap_online(self, mock_requests):
        from bbradar.modules.scanner import check_status
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"version": "2.15.0"}
        mock_requests.get.return_value = resp

        results = check_status("zap")
        assert len(results) == 1
        assert results[0]["status"] == "online"
        assert results[0]["version"] == "2.15.0"

    def test_check_status_offline(self, mock_requests):
        from bbradar.modules.scanner import check_status
        mock_requests.ConnectionError = ConnectionError
        mock_requests.Timeout = TimeoutError
        mock_requests.get.side_effect = ConnectionError("refused")

        results = check_status("zap")
        assert results[0]["status"] == "offline"
        assert "refused" in results[0]["error"].lower()

    def test_detect_scanner_none(self, mock_requests):
        from bbradar.modules.scanner import detect_scanner
        mock_requests.ConnectionError = ConnectionError
        mock_requests.Timeout = TimeoutError
        mock_requests.get.side_effect = ConnectionError("refused")

        result = detect_scanner()
        assert result is None


# ══════════════════════════════════════════════════════════════
# Alert/Issue Import
# ══════════════════════════════════════════════════════════════

class TestAlertImport:
    def test_import_zap_alerts(self, project):
        pid, db = project
        from bbradar.modules.scanner import _import_zap_alerts

        alerts = [
            {
                "name": "Cross Site Scripting (Reflected)",
                "risk": "3",
                "confidence": "3",
                "url": "https://example.com/search?q=<script>",
                "description": "Reflected XSS found",
                "solution": "Encode output",
                "cweid": "79",
                "evidence": "<script>alert(1)</script>",
            },
            {
                "name": "SQL Injection",
                "risk": "3",
                "confidence": "2",
                "url": "https://example.com/api/user?id=1",
                "description": "SQL injection in id parameter",
                "cweid": "89",
            },
            {
                "name": "X-Frame-Options Header Not Set",
                "risk": "1",
                "confidence": "2",
                "url": "https://example.com/",
                "description": "Missing header",
                "cweid": "-1",
            },
        ]

        ids = _import_zap_alerts(alerts, pid, db_path=db)
        assert len(ids) == 3

        # Verify first vuln
        vuln = get_vuln(ids[0], db)
        assert "Cross Site Scripting" in vuln["title"]
        assert vuln["severity"] == "high"
        assert vuln["vuln_type"] == "xss"
        assert vuln["source_tool"] == "zap"
        assert vuln["cwe_id"] == "CWE-79"
        assert vuln["confidence"] == "certain"

        # Verify SQLi
        vuln2 = get_vuln(ids[1], db)
        assert vuln2["vuln_type"] == "sqli"
        assert vuln2["cwe_id"] == "CWE-89"

        # Verify low-severity header issue
        vuln3 = get_vuln(ids[2], db)
        assert vuln3["severity"] == "low"
        assert vuln3["cwe_id"] is None  # cweid was -1

    def test_import_zap_alerts_dedup(self, project):
        pid, db = project
        from bbradar.modules.scanner import _import_zap_alerts

        alerts = [
            {"name": "XSS", "risk": "3", "url": "https://example.com/a", "cweid": "79"},
        ]

        ids1 = _import_zap_alerts(alerts, pid, db_path=db)
        assert len(ids1) == 1

        # Import same alert again — should dedup
        ids2 = _import_zap_alerts(alerts, pid, db_path=db)
        assert len(ids2) == 0

    def test_import_burp_issues(self, project):
        pid, db = project
        from bbradar.modules.scanner import _import_burp_issues

        issues = [
            {
                "issue": {
                    "name": "Reflected cross-site scripting",
                    "severity": "High",
                    "confidence": "Certain",
                    "origin": "https://example.com",
                    "path": "/search",
                    "issueDetail": "XSS in search parameter",
                },
            },
            {
                "issue": {
                    "name": "SQL injection",
                    "severity": "High",
                    "confidence": "Firm",
                    "origin": "https://example.com",
                    "path": "/api/users",
                    "issueDetail": "SQLi via id param",
                },
            },
        ]

        ids = _import_burp_issues(issues, pid, db_path=db)
        assert len(ids) == 2

        vuln = get_vuln(ids[0], db)
        assert vuln["vuln_type"] == "xss"
        assert vuln["source_tool"] == "burp"
        assert vuln["confidence"] == "certain"
        assert vuln["severity"] == "high"

    def test_import_burp_issues_information_severity(self, project):
        pid, db = project
        from bbradar.modules.scanner import _import_burp_issues

        issues = [
            {"issue": {"name": "Robots.txt", "severity": "Information",
                        "confidence": "Firm", "origin": "https://ex.com", "path": "/"}},
        ]
        ids = _import_burp_issues(issues, pid, db_path=db)
        vuln = get_vuln(ids[0], db)
        assert vuln["severity"] == "informational"


# ══════════════════════════════════════════════════════════════
# Vuln Type Classification
# ══════════════════════════════════════════════════════════════

class TestClassification:
    def test_zap_classification(self):
        from bbradar.modules.scanner import _classify_zap_alert
        assert _classify_zap_alert("Cross Site Scripting (Reflected)") == "xss"
        assert _classify_zap_alert("SQL Injection - MySQL") == "sqli"
        assert _classify_zap_alert("Path Traversal") == "path_traversal"
        assert _classify_zap_alert("Server Side Request Forgery") == "ssrf"
        assert _classify_zap_alert("Totally Unknown Thing") == "other"

    def test_burp_classification(self):
        from bbradar.modules.scanner import _classify_burp_issue
        assert _classify_burp_issue("Reflected cross-site scripting") == "xss"
        assert _classify_burp_issue("Blind SQL injection") == "sqli"
        assert _classify_burp_issue("File path traversal") == "path_traversal"
        assert _classify_burp_issue("OS command injection") == "command_injection"
        assert _classify_burp_issue("Random info issue") == "other"

    def test_all_mapped_types_valid(self):
        from bbradar.modules.scanner import _ZAP_TYPE_MAP, _BURP_TYPE_MAP
        for vtype in _ZAP_TYPE_MAP.values():
            assert vtype in VALID_VULN_TYPES or vtype == "other"
        for vtype in _BURP_TYPE_MAP.values():
            assert vtype in VALID_VULN_TYPES or vtype == "other"


# ══════════════════════════════════════════════════════════════
# Scope Sync
# ══════════════════════════════════════════════════════════════

class TestScopeSync:
    def test_scope_sync_zap(self, project, mock_requests):
        pid, db = project
        # Add scope rules
        add_rule(pid, "*.example.com", rule_type="include", db_path=db)
        add_rule(pid, "*.internal.example.com", rule_type="exclude", db_path=db)

        resp = MagicMock()
        resp.json.return_value = {"contextId": "1"}
        mock_requests.get.return_value = resp

        from bbradar.modules.scanner import scope_sync
        result = scope_sync(pid, scanner_type="zap", db_path=db)
        assert result["scanner"] == "zap"
        assert result["includes_pushed"] == 1
        assert result["excludes_pushed"] == 1

    def test_scope_sync_no_rules(self, project, mock_requests):
        pid, db = project
        from bbradar.modules.scanner import scope_sync
        with pytest.raises(ValueError, match="No scope rules"):
            scope_sync(pid, scanner_type="zap", db_path=db)

    def test_scope_sync_burp_not_supported(self, project, mock_requests):
        pid, db = project
        add_rule(pid, "*.example.com", db_path=db)
        from bbradar.modules.scanner import scope_sync
        with pytest.raises(RuntimeError, match="does not support"):
            scope_sync(pid, scanner_type="burp", db_path=db)


# ══════════════════════════════════════════════════════════════
# Scope Pattern Conversion
# ══════════════════════════════════════════════════════════════

class TestScopePatternToRegex:
    def test_wildcard(self):
        from bbradar.modules.scanner import _scope_pattern_to_regex
        regex = _scope_pattern_to_regex("*.example.com", "wildcard")
        assert "example" in regex
        assert ".*" in regex

    def test_exact(self):
        from bbradar.modules.scanner import _scope_pattern_to_regex
        regex = _scope_pattern_to_regex("admin.example.com", "exact")
        assert "admin" in regex

    def test_regex_passthrough(self):
        from bbradar.modules.scanner import _scope_pattern_to_regex
        regex = _scope_pattern_to_regex("^.*\\.example\\.com$", "regex")
        assert regex == "^.*\\.example\\.com$"

    def test_cidr_empty(self):
        from bbradar.modules.scanner import _scope_pattern_to_regex
        regex = _scope_pattern_to_regex("10.0.0.0/24", "cidr")
        assert regex == ""


# ══════════════════════════════════════════════════════════════
# Spider
# ══════════════════════════════════════════════════════════════

class TestSpider:
    def test_spider_zap(self, target, mock_requests):
        tid, pid, db = target

        # Mock spider scan start
        scan_resp = MagicMock()
        scan_resp.json.return_value = {"scan": "1"}

        # Mock spider status (immediately complete)
        status_resp = MagicMock()
        status_resp.json.return_value = {"status": "100"}

        # Mock URLs
        urls_resp = MagicMock()
        urls_resp.json.return_value = {"urls": [
            "https://example.com/",
            "https://example.com/admin",
            "https://example.com/api/v1",
            "https://other.com/",
        ]}

        mock_requests.get.side_effect = [scan_resp, status_resp, urls_resp]

        from bbradar.modules.scanner import spider
        result = spider(tid, scanner_type="zap", db_path=db)
        assert result["scanner"] == "zap"
        assert result["urls_found"] == 3  # only example.com URLs
        assert result["recon_added"] >= 0

    def test_spider_burp_unsupported(self, target, mock_requests):
        tid, pid, db = target
        from bbradar.modules.scanner import spider
        with pytest.raises(RuntimeError, match="does not support"):
            spider(tid, scanner_type="burp", db_path=db)


# ══════════════════════════════════════════════════════════════
# Monitor
# ══════════════════════════════════════════════════════════════

class TestMonitor:
    def test_monitor_cycle(self, project, mock_requests):
        pid, db = project

        resp = MagicMock()
        resp.json.return_value = {"alerts": [
            {"name": "XSS", "risk": "3", "url": "https://example.com/x",
             "confidence": "3", "cweid": "79"},
        ]}
        mock_requests.get.return_value = resp

        from bbradar.modules.scanner import monitor
        stats = monitor(pid, scanner_type="zap", interval=0,
                        max_cycles=2, db_path=db)
        assert stats["cycles"] == 2
        # First cycle imports 1, second cycle sees same alert (dedup within monitor)
        assert stats["total_imported"] == 1

    def test_monitor_burp_unsupported(self, project, mock_requests):
        pid, db = project
        from bbradar.modules.scanner import monitor
        with pytest.raises(RuntimeError, match="ZAP only"):
            monitor(pid, scanner_type="burp", db_path=db)


# ══════════════════════════════════════════════════════════════
# Import Findings (high-level)
# ══════════════════════════════════════════════════════════════

class TestImportFindings:
    def test_import_from_zap(self, project, mock_requests):
        pid, db = project

        resp = MagicMock()
        resp.json.return_value = {"alerts": [
            {"name": "CSRF", "risk": "2", "url": "https://example.com/form",
             "confidence": "2", "cweid": "352"},
        ]}
        mock_requests.get.return_value = resp

        from bbradar.modules.scanner import import_findings
        result = import_findings(pid, scanner_type="zap", db_path=db)
        assert result["total"] == 1
        assert result["imported"] == 1

    def test_import_burp_unsupported(self, project, mock_requests):
        pid, db = project
        from bbradar.modules.scanner import import_findings
        with pytest.raises(RuntimeError, match="per-scan"):
            import_findings(pid, scanner_type="burp", db_path=db)


# ══════════════════════════════════════════════════════════════
# Target URL Conversion
# ══════════════════════════════════════════════════════════════

class TestTargetToUrl:
    def test_domain_gets_https(self):
        from bbradar.modules.scanner import _target_to_url
        assert _target_to_url("example.com") == "https://example.com"

    def test_url_passthrough(self):
        from bbradar.modules.scanner import _target_to_url
        assert _target_to_url("http://example.com") == "http://example.com"
        assert _target_to_url("https://example.com/path") == "https://example.com/path"


# ══════════════════════════════════════════════════════════════
# Workflow Scanner Steps
# ══════════════════════════════════════════════════════════════

class TestWorkflowScannerSteps:
    def test_scanner_step_dry_run(self, target):
        tid, pid, db = target
        from bbradar.modules.workflows import _execute_scanner_step
        step = {"name": "ZAP Spider", "scanner": "zap", "action": "spider"}
        result = _execute_scanner_step(step, "example.com", tid,
                                        dry_run=True, db_path=db)
        assert result["ok"] is True
        assert any("dry run" in l for l in result["lines"])

    def test_scanner_step_unknown_action(self, target):
        tid, pid, db = target
        from bbradar.modules.workflows import _execute_scanner_step
        step = {"name": "Bad", "scanner": "zap", "action": "nonexistent"}
        result = _execute_scanner_step(step, "example.com", tid,
                                        dry_run=False, db_path=db)
        assert result["ok"] is False

    def test_execute_step_delegates_to_scanner(self, target):
        """Verify _execute_step delegates to _execute_scanner_step when scanner key present."""
        tid, pid, db = target
        from bbradar.modules.workflows import _execute_step
        step = {"name": "ZAP Scan", "scanner": "zap", "action": "scan"}
        # dry_run so we don't need a real scanner
        result = _execute_step(step, "example.com", tid,
                               dry_run=True, db_path=db)
        assert result["ok"] is True
        assert result.get("skipped") is True


# ══════════════════════════════════════════════════════════════
# Probe Scanner Suggestions
# ══════════════════════════════════════════════════════════════

class TestProbeScannerSuggestions:
    def test_http_port_triggers_scanner_suggestion(self, target):
        tid, pid, db = target
        # Add HTTP port recon data
        add_recon(tid, "port", "80/tcp", source_tool="nmap", db_path=db)

        intel = get_target_intel(tid, db_path=db)
        suggestions = suggest_actions(intel)

        scanner_suggestions = [s for s in suggestions if s.get("scanner")]
        assert len(scanner_suggestions) >= 2  # ZAP and Burp
        tools = {s["tool"] for s in scanner_suggestions}
        assert "zap" in tools
        assert "burp" in tools

    def test_no_scanner_suggestion_without_http(self, target):
        tid, pid, db = target
        # Add non-HTTP port
        add_recon(tid, "port", "22/tcp", source_tool="nmap", db_path=db)

        intel = get_target_intel(tid, db_path=db)
        suggestions = suggest_actions(intel)

        scanner_suggestions = [s for s in suggestions if s.get("scanner")]
        assert len(scanner_suggestions) == 0


# ══════════════════════════════════════════════════════════════
# Confidence Mapping
# ══════════════════════════════════════════════════════════════

class TestConfidenceMapping:
    def test_zap_confidence_values(self):
        from bbradar.modules.scanner import CONFIDENCE_MAP_ZAP
        assert CONFIDENCE_MAP_ZAP["0"] == "tentative"
        assert CONFIDENCE_MAP_ZAP["2"] == "firm"
        assert CONFIDENCE_MAP_ZAP["3"] == "certain"

    def test_burp_confidence_values(self):
        from bbradar.modules.scanner import CONFIDENCE_MAP_BURP
        assert CONFIDENCE_MAP_BURP["certain"] == "certain"
        assert CONFIDENCE_MAP_BURP["firm"] == "firm"
        assert CONFIDENCE_MAP_BURP["tentative"] == "tentative"
