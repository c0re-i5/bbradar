"""
Tests for new feature modules:
  - jsanalyzer (JS analysis pipeline)
  - param_classifier (parameter classification)
  - analyzer (web page analyzer)
  - differ (attack surface diffing)
"""

import json
import pytest

from bbradar.modules.jsanalyzer import analyze_js_content, discover_js_files, analyze_target
from bbradar.modules.param_classifier import classify_param, classify_target, suggest_tests
from bbradar.modules.analyzer import analyze_page, format_report, _attr
from bbradar.modules.differ import snapshot_recon, list_snapshots, get_snapshot, diff_snapshots
from bbradar.modules.recon import add_recon, bulk_add_recon
from bbradar.modules.projects import create_project
from bbradar.modules.targets import add_target


# ═══════════════════════════════════════════════════════════════════
# JS Analyzer Tests
# ═══════════════════════════════════════════════════════════════════

class TestJSAnalyzer:
    def test_detect_aws_key(self):
        js = 'var key = "AKIAIOSFODNN7EXAMPLE";'
        result = analyze_js_content(js, "https://example.com/app.js")
        assert len(result["secrets"]) >= 1
        assert result["secrets"][0]["type"] == "aws_access_key"

    def test_detect_github_token(self):
        js = 'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";'
        result = analyze_js_content(js)
        assert any(s["type"] == "github_token" for s in result["secrets"])

    def test_detect_slack_webhook(self):
        # Build the URL dynamically to avoid triggering secret scanners
        hook_url = "https://hooks.slack.com/services/" + "TABC/BDEF/" + "x" * 24
        js = f'var hook = "{hook_url}";'
        result = analyze_js_content(js)
        assert any(s["type"] == "slack_webhook" for s in result["secrets"])

    def test_detect_api_endpoints(self):
        js = '''
        fetch("/api/v1/users");
        axios.get("/admin/settings");
        post("/internal/debug/info");
        '''
        result = analyze_js_content(js)
        assert "/api/v1/users" in result["endpoints"]
        assert "/admin/settings" in result["endpoints"]

    def test_detect_internal_ips(self):
        js = 'var backend = "http://192.168.1.100:8080";'
        result = analyze_js_content(js)
        assert "192.168.1.100" in result["internal_ips"]

    def test_detect_s3_bucket(self):
        js = 'var cdn = "my-bucket.s3.amazonaws.com";'
        result = analyze_js_content(js)
        assert len(result["cloud_urls"]) >= 1

    def test_detect_sourcemap(self):
        js = '//# sourceMappingURL=app.js.map'
        result = analyze_js_content(js, "https://cdn.example.com/js/app.js")
        assert len(result["sourcemaps"]) == 1
        assert "app.js.map" in result["sourcemaps"][0]

    def test_detect_firebase(self):
        js = 'var db = "https://myapp-12345.firebaseio.com";'
        result = analyze_js_content(js)
        assert any(c["type"] == "firebase_url" for c in result["cloud_urls"])

    def test_no_false_positives_on_empty(self):
        result = analyze_js_content("")
        assert all(len(v) == 0 for v in result.values())

    def test_detect_jwt(self):
        js = 'var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";'
        result = analyze_js_content(js)
        assert any(s["type"] == "jwt_token" for s in result["secrets"])

    def test_discover_js_files(self, tmp_db):
        pid = create_project("TestProj", db_path=tmp_db)
        tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
        add_recon(tid, "js_file", "https://example.com/app.js", db_path=tmp_db)
        add_recon(tid, "url", "https://example.com/vendor.js", db_path=tmp_db)
        add_recon(tid, "url", "https://example.com/index.html", db_path=tmp_db)

        urls = discover_js_files(tid, db_path=tmp_db)
        assert "https://example.com/app.js" in urls
        assert "https://example.com/vendor.js" in urls
        assert "https://example.com/index.html" not in urls

    def test_analyze_target_no_js(self, tmp_db):
        pid = create_project("TestProj", db_path=tmp_db)
        tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
        result = analyze_target(tid, db_path=tmp_db)
        assert result["js_files"] == 0
        assert result["analyzed"] == 0


# ═══════════════════════════════════════════════════════════════════
# Parameter Classifier Tests
# ═══════════════════════════════════════════════════════════════════

class TestParamClassifier:
    def test_classify_id(self):
        hits = classify_param("id")
        classes = {h["vuln_class"] for h in hits}
        assert "idor" in classes
        assert "sqli" in classes

    def test_classify_url(self):
        hits = classify_param("url")
        classes = {h["vuln_class"] for h in hits}
        assert "ssrf" in classes
        assert "open_redirect" in classes

    def test_classify_search(self):
        hits = classify_param("search")
        classes = {h["vuln_class"] for h in hits}
        assert "xss" in classes

    def test_classify_file(self):
        hits = classify_param("file")
        classes = {h["vuln_class"] for h in hits}
        assert "lfi" in classes

    def test_classify_cmd(self):
        hits = classify_param("cmd")
        classes = {h["vuln_class"] for h in hits}
        assert "rce" in classes

    def test_classify_debug(self):
        hits = classify_param("debug")
        classes = {h["vuln_class"] for h in hits}
        assert "info_leak" in classes

    def test_classify_redirect(self):
        hits = classify_param("redirect_url")
        classes = {h["vuln_class"] for h in hits}
        assert "open_redirect" in classes

    def test_classify_unknown(self):
        hits = classify_param("xyzzy_foobar")
        assert len(hits) == 0

    def test_classify_empty(self):
        assert classify_param("") == []

    def test_classify_user_id(self):
        hits = classify_param("user_id")
        classes = {h["vuln_class"] for h in hits}
        assert "idor" in classes

    def test_confidence_levels(self):
        # Exact match patterns should give high confidence
        hits = classify_param("id")
        idor = [h for h in hits if h["vuln_class"] == "idor"][0]
        assert idor["confidence"] == "high"

    def test_classify_target(self, tmp_db):
        pid = create_project("TestProj", db_path=tmp_db)
        tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
        add_recon(tid, "parameter", "user_id", db_path=tmp_db)
        add_recon(tid, "parameter", "redirect_url", db_path=tmp_db)
        add_recon(tid, "parameter", "randomthing", db_path=tmp_db)

        result = classify_target(tid, db_path=tmp_db)
        assert result["total_params"] == 3
        assert result["classified"] == 2
        assert "idor" in result["classifications"]

    def test_suggest_tests(self, tmp_db):
        pid = create_project("TestProj", db_path=tmp_db)
        tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
        add_recon(tid, "parameter", "user_id (https://example.com/api)", db_path=tmp_db)

        suggestions = suggest_tests(tid, db_path=tmp_db)
        assert len(suggestions) > 0
        assert suggestions[0]["param"] == "user_id"
        assert suggestions[0]["url_context"] == "https://example.com/api"


# ═══════════════════════════════════════════════════════════════════
# Web Page Analyzer Tests
# ═══════════════════════════════════════════════════════════════════

class TestAnalyzer:
    def test_attr_extraction(self):
        assert _attr('<input type="hidden" name="csrf">', "name") == "csrf"
        assert _attr('<input type="hidden" name="csrf">', "type") == "hidden"
        assert _attr('<input>', "name") == ""

    def test_format_report_with_errors(self):
        result = {
            "url": "https://example.com",
            "title": "",
            "errors": ["Failed to fetch https://example.com"],
            "technologies": [], "security_headers": {"present": {}, "missing": []},
            "forms": [], "comments": [], "js_files": [], "links": [],
            "meta_leaks": [], "cookies": [], "endpoints": [],
        }
        report = format_report(result)
        assert "ERROR" in report
        assert "example.com" in report

    def test_format_report_full(self):
        result = {
            "url": "https://example.com",
            "title": "Example Page",
            "errors": [],
            "technologies": [{"name": "Nginx", "source": "header:server", "evidence": "nginx/1.18"}],
            "security_headers": {
                "present": {"x-frame-options": "DENY"},
                "missing": ["strict-transport-security", "content-security-policy"],
            },
            "forms": [{
                "action": "/login",
                "method": "POST",
                "inputs": [
                    {"name": "username", "type": "text", "value": ""},
                    {"name": "password", "type": "password", "value": ""},
                ],
            }],
            "comments": ["TODO: remove debug endpoint"],
            "js_files": ["https://example.com/app.js"],
            "links": {"internal": ["https://example.com/about"], "external": ["https://cdn.jquery.com"]},
            "meta_leaks": [{"name": "generator", "content": "WordPress 6.4"}],
            "cookies": [{"raw": "session=abc", "secure": False, "httponly": True, "samesite": ""}],
            "endpoints": ["/login", "/about", "/api/v1"],
            "stored": {"tech": 1, "header": 2, "js_file": 1, "endpoint": 3, "parameter": 2, "other": 1},
        }
        report = format_report(result)
        assert "Nginx" in report
        assert "strict-transport-security" in report
        assert "/login" in report
        assert "WordPress 6.4" in report
        assert "NO Secure" in report
        assert "Stored" in report


# ═══════════════════════════════════════════════════════════════════
# Attack Surface Differ Tests
# ═══════════════════════════════════════════════════════════════════

class TestDiffer:
    def test_snapshot_and_list(self, tmp_db):
        pid = create_project("TestProj", db_path=tmp_db)
        tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
        add_recon(tid, "subdomain", "api.example.com", db_path=tmp_db)
        add_recon(tid, "subdomain", "www.example.com", db_path=tmp_db)

        result = snapshot_recon(pid, label="baseline", db_path=tmp_db)
        assert result["snapshot_id"] > 0

        snaps = list_snapshots(pid, db_path=tmp_db)
        assert len(snaps) == 1
        assert snaps[0]["label"] == "baseline"
        assert snaps[0]["entry_count"] == 2

    def test_get_snapshot(self, tmp_db):
        pid = create_project("TestProj", db_path=tmp_db)
        tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
        add_recon(tid, "subdomain", "api.example.com", db_path=tmp_db)

        result = snapshot_recon(pid, db_path=tmp_db)
        snap = get_snapshot(result["snapshot_id"], db_path=tmp_db)
        assert snap is not None
        assert snap["entry_count"] == 1
        assert len(snap["data"]) == 1
        assert snap["data"][0]["value"] == "api.example.com"

    def test_diff_detects_additions(self, tmp_db):
        pid = create_project("TestProj", db_path=tmp_db)
        tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
        add_recon(tid, "subdomain", "api.example.com", db_path=tmp_db)

        r1 = snapshot_recon(pid, db_path=tmp_db)

        # Add new recon
        add_recon(tid, "subdomain", "admin.example.com", db_path=tmp_db)
        add_recon(tid, "port", "8080", db_path=tmp_db)

        r2 = snapshot_recon(pid, db_path=tmp_db)

        diff = diff_snapshots(r1["snapshot_id"], r2["snapshot_id"], db_path=tmp_db)
        assert len(diff["added"]) == 2
        assert len(diff["removed"]) == 0
        assert diff["summary"]["subdomain"]["added"] == 1
        assert diff["summary"]["port"]["added"] == 1

    def test_diff_detects_removals(self, tmp_db):
        pid = create_project("TestProj", db_path=tmp_db)
        tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
        add_recon(tid, "subdomain", "api.example.com", db_path=tmp_db)
        add_recon(tid, "subdomain", "old.example.com", db_path=tmp_db)

        r1 = snapshot_recon(pid, db_path=tmp_db)

        # Simulate removal
        from bbradar.core.database import get_connection
        with get_connection(tmp_db) as conn:
            conn.execute("DELETE FROM recon_data WHERE value = 'old.example.com'")

        r2 = snapshot_recon(pid, db_path=tmp_db)
        diff = diff_snapshots(r1["snapshot_id"], r2["snapshot_id"], db_path=tmp_db)
        assert len(diff["removed"]) == 1
        assert diff["removed"][0]["value"] == "old.example.com"

    def test_empty_project(self, tmp_db):
        pid = create_project("EmptyProj", db_path=tmp_db)
        result = snapshot_recon(pid, db_path=tmp_db)
        snap = get_snapshot(result["snapshot_id"], db_path=tmp_db)
        assert snap["entry_count"] == 0
        assert snap["data"] == []

    def test_diff_no_changes(self, tmp_db):
        pid = create_project("TestProj", db_path=tmp_db)
        tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
        add_recon(tid, "subdomain", "api.example.com", db_path=tmp_db)

        r1 = snapshot_recon(pid, db_path=tmp_db)
        r2 = snapshot_recon(pid, db_path=tmp_db)

        diff = diff_snapshots(r1["snapshot_id"], r2["snapshot_id"], db_path=tmp_db)
        assert len(diff["added"]) == 0
        assert len(diff["removed"]) == 0
