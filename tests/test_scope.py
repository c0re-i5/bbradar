"""
Tests for scope rules engine — pattern matching, import, validation.
"""

import json
import pytest
from bbradar.modules.projects import create_project
from bbradar.modules.targets import add_target
from bbradar.modules.scope import (
    add_rule, list_rules, delete_rule, clear_rules, get_rule,
    check_scope, check_scope_batch, import_from_text,
    validate_targets, auto_scope_targets, scope_overview,
)


@pytest.fixture
def project(tmp_db):
    """Create a project and return (project_id, db_path)."""
    pid = create_project("Scope Test", db_path=tmp_db)
    return pid, tmp_db


class TestAddRule:
    def test_wildcard_auto_detect(self, project):
        pid, db = project
        rid = add_rule(pid, "*.example.com", db_path=db)
        rule = get_rule(rid, db_path=db)
        assert rule["pattern_type"] == "wildcard"
        assert rule["rule_type"] == "include"

    def test_cidr_auto_detect(self, project):
        pid, db = project
        rid = add_rule(pid, "10.0.0.0/24", db_path=db)
        rule = get_rule(rid, db_path=db)
        assert rule["pattern_type"] == "cidr"

    def test_regex_explicit(self, project):
        pid, db = project
        rid = add_rule(pid, "^api-[0-9]+\\.example\\.com$", pattern_type="regex", db_path=db)
        rule = get_rule(rid, db_path=db)
        assert rule["pattern_type"] == "regex"

    def test_empty_pattern_rejected(self, project):
        pid, db = project
        with pytest.raises(ValueError, match="empty"):
            add_rule(pid, "", db_path=db)

    def test_invalid_rule_type(self, project):
        pid, db = project
        with pytest.raises(ValueError, match="include.*exclude"):
            add_rule(pid, "test.com", rule_type="maybe", db_path=db)

    def test_exclude_rule(self, project):
        pid, db = project
        rid = add_rule(pid, "admin.example.com", rule_type="exclude", db_path=db)
        rule = get_rule(rid, db_path=db)
        assert rule["rule_type"] == "exclude"


class TestWildcardMatching:
    def test_subdomain_match(self, project):
        pid, db = project
        add_rule(pid, "*.example.com", db_path=db)
        result = check_scope(pid, "sub.example.com", db_path=db)
        assert result["in_scope"] is True

    def test_bare_domain_match(self, project):
        """*.example.com should also match example.com itself."""
        pid, db = project
        add_rule(pid, "*.example.com", db_path=db)
        result = check_scope(pid, "example.com", db_path=db)
        assert result["in_scope"] is True

    def test_deep_subdomain(self, project):
        pid, db = project
        add_rule(pid, "*.example.com", db_path=db)
        result = check_scope(pid, "deep.sub.example.com", db_path=db)
        assert result["in_scope"] is True

    def test_url_with_protocol(self, project):
        """Should strip protocol before matching."""
        pid, db = project
        add_rule(pid, "*.example.com", db_path=db)
        result = check_scope(pid, "https://api.example.com/v1", db_path=db)
        assert result["in_scope"] is True

    def test_no_match(self, project):
        pid, db = project
        add_rule(pid, "*.example.com", db_path=db)
        result = check_scope(pid, "other.org", db_path=db)
        assert result["in_scope"] is False


class TestCIDRMatching:
    def test_ip_in_range(self, project):
        pid, db = project
        add_rule(pid, "10.0.0.0/24", db_path=db)
        result = check_scope(pid, "10.0.0.42", db_path=db)
        assert result["in_scope"] is True

    def test_ip_out_of_range(self, project):
        pid, db = project
        add_rule(pid, "10.0.0.0/24", db_path=db)
        result = check_scope(pid, "10.0.1.1", db_path=db)
        assert result["in_scope"] is False

    def test_single_host_cidr(self, project):
        pid, db = project
        add_rule(pid, "192.168.1.1/32", db_path=db)
        result = check_scope(pid, "192.168.1.1", db_path=db)
        assert result["in_scope"] is True


class TestExcludeOverride:
    def test_exclude_beats_include(self, project):
        """At same priority, exclude should win."""
        pid, db = project
        add_rule(pid, "*.example.com", db_path=db)
        add_rule(pid, "admin.example.com", rule_type="exclude", db_path=db)
        result = check_scope(pid, "admin.example.com", db_path=db)
        assert result["in_scope"] is False

    def test_include_still_works(self, project):
        pid, db = project
        add_rule(pid, "*.example.com", db_path=db)
        add_rule(pid, "admin.example.com", rule_type="exclude", db_path=db)
        result = check_scope(pid, "app.example.com", db_path=db)
        assert result["in_scope"] is True

    def test_priority_override(self, project):
        """Higher priority include should beat lower priority exclude."""
        pid, db = project
        add_rule(pid, "admin.example.com", rule_type="exclude", priority=0, db_path=db)
        add_rule(pid, "admin.example.com", rule_type="include", priority=10, db_path=db)
        result = check_scope(pid, "admin.example.com", db_path=db)
        assert result["in_scope"] is True


class TestNoRules:
    def test_no_rules_returns_none(self, project):
        """With no rules, result is None (indeterminate — no rules to evaluate)."""
        pid, db = project
        result = check_scope(pid, "anything.com", db_path=db)
        assert result["in_scope"] is None


class TestBatchCheck:
    def test_batch_results(self, project):
        pid, db = project
        add_rule(pid, "*.example.com", db_path=db)
        results = check_scope_batch(pid, ["a.example.com", "other.org"], db_path=db)
        assert len(results) == 2
        assert results[0]["in_scope"] is True
        assert results[1]["in_scope"] is False


class TestImportFromText:
    def test_simple_list(self, project):
        pid, db = project
        result = import_from_text(pid, "example.com\ntest.io\n*.api.com", db_path=db)
        assert result["added"] == 3
        rules = list_rules(pid, db_path=db)
        assert len(rules) == 3

    def test_labeled_format(self, project):
        pid, db = project
        text = "IN: *.example.com\nOUT: admin.example.com"
        result = import_from_text(pid, text, db_path=db)
        assert result["added"] == 2
        rules = list_rules(pid, db_path=db)
        in_rules = [r for r in rules if r["rule_type"] == "include"]
        ex_rules = [r for r in rules if r["rule_type"] == "exclude"]
        assert len(in_rules) == 1
        assert len(ex_rules) == 1

    def test_exclamation_prefix(self, project):
        pid, db = project
        text = "*.example.com\n!admin.example.com"
        result = import_from_text(pid, text, db_path=db)
        assert result["added"] == 2


class TestCRUD:
    def test_delete_rule(self, project):
        pid, db = project
        rid = add_rule(pid, "test.com", db_path=db)
        delete_rule(rid, db_path=db)
        assert get_rule(rid, db_path=db) is None

    def test_clear_rules(self, project):
        pid, db = project
        add_rule(pid, "a.com", db_path=db)
        add_rule(pid, "b.com", db_path=db)
        count = clear_rules(pid, db_path=db)
        assert count == 2
        assert list_rules(pid, db_path=db) == []


class TestValidateTargets:
    def test_mismatches_detected(self, project):
        pid, db = project
        add_rule(pid, "*.example.com", db_path=db)
        add_target(pid, "domain", "app.example.com", db_path=db)
        add_target(pid, "domain", "other.org", db_path=db)  # in_scope=1 by default
        result = validate_targets(pid, db_path=db)
        # other.org should be flagged as mismatch (default in_scope=1 but no matching rule)
        assert result["mismatches"] or result["unmatched"]

    def test_auto_scope_fixes(self, project):
        pid, db = project
        add_rule(pid, "*.example.com", db_path=db)
        add_target(pid, "domain", "app.example.com", db_path=db)
        add_target(pid, "domain", "other.org", db_path=db)
        result = auto_scope_targets(pid, dry_run=False, db_path=db)
        assert result["changes"]  # other.org should be flipped to out-of-scope


class TestScopeOverview:
    def test_overview_structure(self, project):
        pid, db = project
        add_rule(pid, "*.example.com", db_path=db)
        add_rule(pid, "admin.example.com", rule_type="exclude", db_path=db)
        ov = scope_overview(pid, db_path=db)
        assert ov["rules_total"] == 2
        assert len(ov["includes"]) == 1
        assert len(ov["excludes"]) == 1
