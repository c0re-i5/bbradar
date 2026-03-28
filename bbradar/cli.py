#!/usr/bin/env python3
"""
BBRadar CLI — Bug Bounty Hunting Platform.

Usage:
    bb <command> <subcommand> [options]

Commands:
    project     Manage bug bounty programs / engagements
    target      Manage scope targets (domains, IPs, URLs)
    recon       Manage reconnaissance data
    vuln        Track vulnerabilities / findings
    note        Assessment notes
    report      Generate reports
    workflow    Run assessment workflows
    wizard      Interactive guided wizards for common tasks
    templates   Browse / search the vulnerability knowledge base
    ingest      Ingest tool output and auto-create findings
    kb          Knowledge base — sync & search CWE, CAPEC, VRT, Nuclei
    scope       Manage scope rules
    h1          HackerOne API — programs, reports, earnings
    dashboard   Combined BBRadar + HackerOne dashboard
    audit       View / manage audit log
    evidence    Evidence file management
    config      View/edit configuration
    db          Database management — backup, restore, migrate
    init        Initialize BBRadar (first-time setup)
    status      Show current workspace status
"""

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path

from .core.database import init_db, get_db_path
from .core.config import (
    load_config, save_config, ensure_dirs, set_config_value, get_config_value,
    DEFAULTS, get_active_project, set_active_project, clear_active_project,
)
from .core.audit import get_audit_log
from .core.utils import format_table, severity_color, confirm, set_no_color
from .modules import projects, targets, recon, vulns, notes, reports, workflows
from .modules import vuln_templates, knowledgebase, ingest, scope, hackerone, notifier
from .modules.wizards import wizard_project, wizard_target, wizard_vuln, quick_vuln


# ═══════════════════════════════════════════════════════════════════
# Argument Parser
# ═══════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bb",
        description="BBRadar — Bug Bounty Hunting Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Global flags
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--no-color", dest="no_color", action="store_true",
                        help="Disable colored output")
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # --- init ---
    sub.add_parser("init", help="Initialize BBRadar (first-time setup)")

    # --- status ---
    sub.add_parser("status", help="Show workspace status")

    # --- use (active project context) ---
    p_use = sub.add_parser("use", help="Set the active project (avoids typing project_id every time)")
    p_use.add_argument("project_id", nargs="?", type=int, help="Project ID to activate (omit to show current)")
    p_use.add_argument("--clear", action="store_true", help="Clear the active project")

    # --- completion ---
    p_comp = sub.add_parser("completion", help="Generate shell tab-completion script")
    p_comp.add_argument("shell", choices=["bash", "zsh", "fish"], help="Shell type")

    # --- project ---
    p_proj = sub.add_parser("project", help="Manage projects")
    sp = p_proj.add_subparsers(dest="subcmd")

    p = sp.add_parser("create", help="Create a new project")
    p.add_argument("name", help="Project name")
    p.add_argument("--platform", "-p", help="Platform (hackerone, bugcrowd, intigriti, private)")
    p.add_argument("--url", help="Program URL")
    p.add_argument("--scope", help="Scope description")
    p.add_argument("--rules", help="Rules of engagement")

    p = sp.add_parser("list", help="List projects")
    p.add_argument("--status", "-s", help="Filter by status")

    p = sp.add_parser("show", help="Show project details")
    p.add_argument("id", type=int, help="Project ID")

    p = sp.add_parser("update", help="Update a project")
    p.add_argument("id", type=int, help="Project ID")
    p.add_argument("--name", help="New name")
    p.add_argument("--platform", help="Platform")
    p.add_argument("--url", help="Program URL")
    p.add_argument("--status", "-s", help="Status (active/paused/completed/archived)")
    p.add_argument("--scope", help="Scope text")
    p.add_argument("--rules", help="Rules text")

    p = sp.add_parser("delete", help="Delete a project")
    p.add_argument("id", type=int, help="Project ID")

    p = sp.add_parser("stats", help="Show project statistics")
    p.add_argument("id", type=int, help="Project ID")

    # --- target ---
    p_tgt = sub.add_parser("target", help="Manage targets")
    sp = p_tgt.add_subparsers(dest="subcmd")

    p = sp.add_parser("add", help="Add a target")
    p.add_argument("project_id", nargs="?", type=int, help="Project ID (uses active project if omitted)")
    p.add_argument("value", nargs="?", help="Target value (domain, IP, URL)")
    p.add_argument("--project", "-p", type=int, dest="project", help="Project ID")
    p.add_argument("--type", "-t", default="domain", help="Asset type (domain/ip/url/wildcard/api/cidr)")
    p.add_argument("--tier", help="Priority tier (critical/high/medium/low)")
    p.add_argument("--out-of-scope", action="store_true", help="Mark as out of scope")
    p.add_argument("--notes", "-n", help="Notes")
    p.add_argument("--stdin", action="store_true", help="Read targets from stdin (one per line)")

    p = sp.add_parser("list", help="List targets")
    p.add_argument("project_id", nargs="?", type=int, help="Project ID (uses active project if omitted)")
    p.add_argument("--project", "-p", type=int, dest="project", help="Project ID")
    p.add_argument("--type", "-t", help="Filter by asset type")
    p.add_argument("--in-scope", action="store_true", help="In-scope only")
    p.add_argument("--out-of-scope", action="store_true", help="Out-of-scope only")

    p = sp.add_parser("import", help="Import targets from file")
    p.add_argument("project_id", nargs="?", type=int, help="Project ID (uses active project if omitted)")
    p.add_argument("file", help="File path (one target per line)")
    p.add_argument("--project", "-p", type=int, dest="project", help="Project ID")
    p.add_argument("--type", "-t", default="domain", help="Asset type")

    p = sp.add_parser("update", help="Update a target")
    p.add_argument("id", type=int, help="Target ID")
    p.add_argument("--tier", help="Priority tier")
    p.add_argument("--notes", "-n", help="Notes")
    p.add_argument("--out-of-scope", action="store_true", help="Mark out of scope")
    p.add_argument("--in-scope", action="store_true", help="Mark in scope")

    p = sp.add_parser("delete", help="Delete a target")
    p.add_argument("id", type=int, help="Target ID")

    # --- recon ---
    p_recon = sub.add_parser("recon", help="Manage recon data")
    sp = p_recon.add_subparsers(dest="subcmd")

    p = sp.add_parser("add", help="Add recon data")
    p.add_argument("target_id", type=int, help="Target ID")
    p.add_argument("data_type", help="Data type (subdomain/port/url/tech/...)")
    p.add_argument("value", nargs="?", help="Data value")
    p.add_argument("--tool", help="Source tool")
    p.add_argument("--stdin", action="store_true", help="Read values from stdin (one per line)")

    p = sp.add_parser("list", help="List recon data")
    p.add_argument("--target", "-t", type=int, help="Target ID")
    p.add_argument("--project", "-p", type=int, help="Project ID")
    p.add_argument("--type", help="Filter by data type")
    p.add_argument("--tool", help="Filter by source tool")
    p.add_argument("--limit", type=int, default=50, help="Max results")

    p = sp.add_parser("import", help="Import recon from file")
    p.add_argument("target_id", type=int, help="Target ID")
    p.add_argument("file", help="File path")
    p.add_argument("data_type", help="Data type")
    p.add_argument("--tool", help="Source tool name")

    p = sp.add_parser("summary", help="Show recon data summary")
    p.add_argument("--target", "-t", type=int, help="Target ID")
    p.add_argument("--project", "-p", type=int, help="Project ID")

    p = sp.add_parser("export", help="Export recon data to file")
    p.add_argument("--target", "-t", type=int, help="Target ID")
    p.add_argument("--project", "-p", type=int, help="Project ID")
    p.add_argument("--type", help="Data type to export")
    p.add_argument("--output", "-o", help="Output file path")

    p = sp.add_parser("run", help="Run a tool and ingest results")
    p.add_argument("tool_name", help="Tool to run (subfinder/nmap/httpx)")
    p.add_argument("target_id", type=int, help="Target ID")
    p.add_argument("--args", "-a", default="", help="Extra tool arguments")

    # --- vuln ---
    p_vuln = sub.add_parser("vuln", help="Track vulnerabilities")
    sp = p_vuln.add_subparsers(dest="subcmd")

    p = sp.add_parser("create", help="Create a finding")
    p.add_argument("project_id", nargs="?", type=int, help="Project ID (uses active project if omitted)")
    p.add_argument("title", help="Vulnerability title")
    p.add_argument("--project", "-p", type=int, dest="project", help="Project ID")
    p.add_argument("--severity", "-s", default="medium", help="Severity (critical/high/medium/low/informational)")
    p.add_argument("--type", "-t", help="Vuln type (xss/sqli/ssrf/...)")
    p.add_argument("--target", type=int, help="Target ID")
    p.add_argument("--description", "-d", help="Description")
    p.add_argument("--impact", help="Impact statement")
    p.add_argument("--repro", help="Reproduction steps")
    p.add_argument("--request", help="HTTP request")
    p.add_argument("--response", help="HTTP response")
    p.add_argument("--remediation", help="Remediation advice")
    p.add_argument("--cvss", type=float, help="CVSS score")
    p.add_argument("--cvss-vector", help="CVSS vector string")

    p = sp.add_parser("list", help="List vulnerabilities")
    p.add_argument("--project", "-p", type=int, help="Project ID")
    p.add_argument("--severity", "-s", help="Filter by severity")
    p.add_argument("--status", help="Filter by status")
    p.add_argument("--type", "-t", help="Filter by type")

    p = sp.add_parser("show", help="Show vulnerability details")
    p.add_argument("id", type=int, help="Vuln ID")

    p = sp.add_parser("update", help="Update a vulnerability")
    p.add_argument("id", type=int, help="Vuln ID")
    p.add_argument("--severity", "-s", help="Severity")
    p.add_argument("--status", help="Status (new/confirmed/reported/accepted/duplicate/resolved)")
    p.add_argument("--type", "-t", help="Vuln type")
    p.add_argument("--title", help="Title")
    p.add_argument("--description", "-d", help="Description")
    p.add_argument("--impact", help="Impact")
    p.add_argument("--repro", help="Reproduction steps")
    p.add_argument("--request", help="HTTP request")
    p.add_argument("--response", help="HTTP response")
    p.add_argument("--remediation", help="Remediation")
    p.add_argument("--bounty", type=float, help="Bounty amount")
    p.add_argument("--report-url", help="Submitted report URL")

    p = sp.add_parser("delete", help="Delete a vulnerability")
    p.add_argument("id", type=int, help="Vuln ID")

    p = sp.add_parser("evidence", help="Add evidence to a vuln")
    p.add_argument("vuln_id", type=int, help="Vuln ID")
    p.add_argument("file", help="Evidence file path")

    p = sp.add_parser("stats", help="Vulnerability statistics")
    p.add_argument("--project", "-p", type=int, help="Project ID")

    p = sp.add_parser("quick", help="Quick-log a vuln from a template")
    p.add_argument("template_key", help="Template key (e.g. xss-reflected)")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")
    p.add_argument("endpoint", help="Affected endpoint")
    p.add_argument("--param", help="Vulnerable parameter")
    p.add_argument("--target", help="Target name / domain")
    p.add_argument("--target-id", type=int, help="Target ID")
    p.add_argument("--repro", help="Reproduction steps")
    p.add_argument("--request", help="HTTP request")

    p = sp.add_parser("transitions", help="Show allowed status transitions")
    p.add_argument("id", type=int, help="Vuln ID")

    p = sp.add_parser("duplicates", help="Find potential duplicate vulns")
    p.add_argument("id", type=int, help="Vuln ID")

    p = sp.add_parser("merge", help="Merge two vulns")
    p.add_argument("source_id", type=int, help="Source vuln ID (will be marked duplicate)")
    p.add_argument("target_id", type=int, help="Target vuln ID (will receive merged data)")

    # --- note ---
    p_note = sub.add_parser("note", help="Assessment notes")
    sp = p_note.add_subparsers(dest="subcmd")

    p = sp.add_parser("add", help="Add a note")
    p.add_argument("content", help="Note content (use - for stdin)")
    p.add_argument("--title", help="Note title")
    p.add_argument("--project", "-p", type=int, help="Project ID")
    p.add_argument("--target", "-t", type=int, help="Target ID")
    p.add_argument("--vuln", "-v", type=int, help="Vuln ID")
    p.add_argument("--tags", help="Comma-separated tags")

    p = sp.add_parser("list", help="List notes")
    p.add_argument("--project", "-p", type=int, help="Project ID")
    p.add_argument("--target", "-t", type=int, help="Target ID")
    p.add_argument("--vuln", "-v", type=int, help="Vuln ID")
    p.add_argument("--tag", help="Filter by tag")
    p.add_argument("--search", "-s", help="Full-text search")

    p = sp.add_parser("show", help="Show a note")
    p.add_argument("id", type=int, help="Note ID")

    p = sp.add_parser("edit", help="Edit a note")
    p.add_argument("id", type=int, help="Note ID")
    p.add_argument("--content", help="New content")
    p.add_argument("--title", help="New title")
    p.add_argument("--tags", help="New tags")

    p = sp.add_parser("delete", help="Delete a note")
    p.add_argument("id", type=int, help="Note ID")

    p = sp.add_parser("export", help="Export notes to markdown")
    p.add_argument("--project", "-p", type=int, help="Project ID")
    p.add_argument("--output", "-o", help="Output file path")

    # --- report ---
    p_rpt = sub.add_parser("report", help="Generate reports")
    sp = p_rpt.add_subparsers(dest="subcmd")

    p = sp.add_parser("vuln", help="Generate single vuln report")
    p.add_argument("vuln_id", type=int, help="Vuln ID")
    p.add_argument("--format", "-f", choices=["markdown", "html", "pdf"], default="markdown")
    p.add_argument("--output", "-o", help="Output file path")

    p = sp.add_parser("full", help="Generate full project report")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")
    p.add_argument("--format", "-f", choices=["markdown", "html", "pdf"], default="markdown")
    p.add_argument("--output", "-o", help="Output file path")

    p = sp.add_parser("executive", help="Generate executive summary")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")
    p.add_argument("--format", "-f", choices=["markdown", "html", "pdf"], default="markdown")
    p.add_argument("--output", "-o", help="Output file path")

    p = sp.add_parser("list", help="List generated reports")
    p.add_argument("--project", "-p", type=int, help="Project ID")

    # --- wizard ---
    p_wiz = sub.add_parser("wizard", help="Interactive guided wizards")
    sp_wiz = p_wiz.add_subparsers(dest="subcmd")
    sp_wiz.add_parser("project", help="Create a new project (guided)")
    sp_wiz.add_parser("target", help="Add a target (guided)")
    sp_wiz.add_parser("vuln", help="Log a vulnerability (guided, with template picker)")

    # --- templates ---
    p_tpl = sub.add_parser("templates", help="Vulnerability knowledge base")
    sp_tpl = p_tpl.add_subparsers(dest="subcmd")

    sp_tpl.add_parser("list", help="List all vulnerability templates")

    p = sp_tpl.add_parser("show", help="Show a template in detail")
    p.add_argument("key", help="Template key (e.g. xss-reflected)")

    p = sp_tpl.add_parser("search", help="Search templates by keyword")
    p.add_argument("query", help="Search query")

    sp_tpl.add_parser("categories", help="List templates grouped by OWASP category")

    # --- scope ---
    p_scope = sub.add_parser("scope", help="Manage scope rules — define what's in and out of scope")
    sp_scope = p_scope.add_subparsers(dest="subcmd")

    p = sp_scope.add_parser("add", help="Add an in-scope rule")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")
    p.add_argument("pattern", help="Scope pattern (e.g. *.example.com, 10.0.0.0/24, !admin.example.com)")
    p.add_argument("--type", "-t", choices=["include", "exclude"], default="include",
                   help="Rule type (default: include)")
    p.add_argument("--pattern-type", choices=["wildcard", "cidr", "regex", "exact"],
                   help="Pattern type (auto-detected if omitted)")
    p.add_argument("--category", choices=["domain", "ip", "url", "general"],
                   help="Asset category this rule applies to")
    p.add_argument("--priority", type=int, default=0, help="Priority (higher wins)")
    p.add_argument("--notes", "-n", help="Notes")

    p = sp_scope.add_parser("exclude", help="Add an exclusion rule (shortcut)")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")
    p.add_argument("pattern", help="Pattern to exclude")
    p.add_argument("--priority", type=int, default=0, help="Priority")
    p.add_argument("--notes", "-n", help="Notes")

    p = sp_scope.add_parser("list", help="List all scope rules")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")

    p = sp_scope.add_parser("delete", help="Delete a scope rule")
    p.add_argument("rule_id", type=int, help="Rule ID")

    p = sp_scope.add_parser("clear", help="Remove all scope rules for a project")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")

    p = sp_scope.add_parser("check", help="Check if a value is in scope")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")
    p.add_argument("value", help="Value to check (domain, IP, URL)")

    p = sp_scope.add_parser("check-file", help="Check all values in a file against scope")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")
    p.add_argument("file", help="File with one value per line")

    p = sp_scope.add_parser("import", help="Import scope rules from file (text, H1 JSON, Bugcrowd JSON)")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")
    p.add_argument("file", help="Scope file to import")

    p = sp_scope.add_parser("validate", help="Validate targets against scope rules")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")
    p.add_argument("--fix", action="store_true", help="Auto-fix target in_scope flags")

    p = sp_scope.add_parser("overview", help="Show scope overview for a project")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")

    sp_scope.add_parser("wizard", help="Interactive scope definition wizard")

    # --- ingest ---
    p_ing = sub.add_parser("ingest", help="Ingest tool output and auto-create findings")
    sp_ing = p_ing.add_subparsers(dest="subcmd")

    p = sp_ing.add_parser("file", help="Ingest a single tool output file")
    p.add_argument("filepath", help="Path to tool output file")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID to ingest into (default: active project)")
    p.add_argument("--tool", "-t", help="Tool name (auto-detected if omitted)")
    p.add_argument("--dry-run", action="store_true", help="Parse and show results without creating vulns")
    p.add_argument("--no-enrich", action="store_true", help="Skip KB enrichment")
    p.add_argument("--min-severity", default="informational",
                   choices=["critical", "high", "medium", "low", "informational"],
                   help="Minimum severity to import (default: informational)")
    p.add_argument("--scope-check", action="store_true",
                   help="Filter findings against project scope rules")

    p = sp_ing.add_parser("dir", help="Ingest all tool outputs from a directory")
    p.add_argument("dirpath", help="Directory containing tool output files")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID to ingest into (default: active project)")
    p.add_argument("--dry-run", action="store_true", help="Parse and show results without creating vulns")
    p.add_argument("--no-enrich", action="store_true", help="Skip KB enrichment")
    p.add_argument("--min-severity", default="informational",
                   choices=["critical", "high", "medium", "low", "informational"],
                   help="Minimum severity to import")
    p.add_argument("--scope-check", action="store_true",
                   help="Filter findings against project scope rules")

    p = sp_ing.add_parser("pipe", help="Ingest tool output from stdin")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID to ingest into (default: active project)")
    p.add_argument("--tool", "-t", required=True, help="Tool name (required for stdin)")
    p.add_argument("--dry-run", action="store_true", help="Parse and show results without creating vulns")
    p.add_argument("--no-enrich", action="store_true", help="Skip KB enrichment")
    p.add_argument("--min-severity", default="informational",
                   choices=["critical", "high", "medium", "low", "informational"],
                   help="Minimum severity to import")
    p.add_argument("--scope-check", action="store_true",
                   help="Filter findings against project scope rules")

    sp_ing.add_parser("tools", help="List supported tools / parsers")

    p = sp_ing.add_parser("summary", help="Show ingest summary for a project")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="Project ID (default: active project)")

    # --- kb (knowledge base) ---
    p_kb = sub.add_parser("kb", help="Knowledge base — CWE, CAPEC, VRT, Nuclei, CVE, KEV, EPSS")
    sp_kb = p_kb.add_subparsers(dest="subcmd")

    p = sp_kb.add_parser("sync", help="Download / update KB sources")
    p.add_argument("--source", "-s",
                   choices=["cwe", "capec", "vrt", "nuclei", "cve", "kev", "epss", "all"],
                   default="all", help="Source to sync (default: all)")
    p.add_argument("--force", "-f", action="store_true",
                   help="Force re-download even if recently synced")

    sp_kb.add_parser("status", help="Show KB sync status and record counts")

    p = sp_kb.add_parser("search", help="Search across all KB sources")
    p.add_argument("query", help="Search query")

    p = sp_kb.add_parser("cwe", help="Look up a CWE by ID")
    p.add_argument("id", help="CWE ID (e.g. 79 or CWE-79)")

    p = sp_kb.add_parser("capec", help="Look up a CAPEC by ID")
    p.add_argument("id", help="CAPEC ID (e.g. 1 or CAPEC-1)")

    p = sp_kb.add_parser("vrt", help="Browse Bugcrowd VRT")
    p.add_argument("category", nargs="?", help="Category to filter (optional)")

    p = sp_kb.add_parser("nuclei", help="Search Nuclei templates")
    p.add_argument("query", nargs="?", help="Search query")
    p.add_argument("--severity", "-s", help="Filter by severity")
    p.add_argument("--cwe", help="Filter by CWE ID")
    p.add_argument("--tag", help="Filter by tag")
    p.add_argument("--limit", "-n", type=int, default=30, help="Max results")

    p = sp_kb.add_parser("cve", help="Look up a CVE by ID (with KEV + EPSS data)")
    p.add_argument("id", help="CVE ID (e.g. CVE-2024-1234)")

    p = sp_kb.add_parser("kev", help="List recently added CISA KEV entries")
    p.add_argument("--limit", "-n", type=int, default=20, help="Max results")
    p.add_argument("--search", help="Search KEV entries")

    p = sp_kb.add_parser("enrich", help="Enrich a vulnerability with KB data")
    p.add_argument("vuln_id", type=int, help="Vulnerability ID to enrich")

    # --- workflow ---
    p_wf = sub.add_parser("workflow", help="Run assessment workflows")
    sp = p_wf.add_subparsers(dest="subcmd")

    sp.add_parser("list", help="List available workflows")

    p = sp.add_parser("run", help="Run a workflow")
    p.add_argument("name", help="Workflow name or path")
    p.add_argument("target_id", type=int, help="Target ID")
    p.add_argument("--project", "-p", type=int, help="Project ID")
    p.add_argument("--dry-run", action="store_true", help="Show commands without executing")

    p = sp.add_parser("show", help="Show workflow run details")
    p.add_argument("run_id", type=int, help="Workflow run ID")

    p = sp.add_parser("history", help="Workflow run history")
    p.add_argument("--project", "-p", type=int, help="Project ID")
    p.add_argument("--target", "-t", type=int, help="Target ID")

    p = sp.add_parser("preflight", help="Check if required tools are installed")
    p.add_argument("name", help="Workflow name or path")

    # --- evidence ---
    p_ev = sub.add_parser("evidence", help="Evidence file management")
    sp_ev = p_ev.add_subparsers(dest="subcmd")

    sp_ev.add_parser("stats", help="Show evidence storage statistics")
    sp_ev.add_parser("orphans", help="List orphaned evidence files")

    p = sp_ev.add_parser("cleanup", help="Remove orphaned evidence files")
    p.add_argument("--execute", action="store_true",
                   help="Actually delete files (default: dry run)")

    # --- audit ---
    p_audit = sub.add_parser("audit", help="View audit log")
    sp_audit = p_audit.add_subparsers(dest="subcmd")

    p = sp_audit.add_parser("log", help="View audit log entries")
    p.add_argument("--entity-type", "-e", help="Filter by entity type")
    p.add_argument("--entity-id", type=int, help="Filter by entity ID")
    p.add_argument("--limit", "-n", type=int, default=30, help="Max results")

    sp_audit.add_parser("stats", help="Show audit log statistics")

    p = sp_audit.add_parser("purge", help="Purge old audit log entries")
    p.add_argument("--days", "-d", type=int, default=90, help="Delete entries older than N days (default: 90)")

    p = sp_audit.add_parser("export", help="Export audit log to JSON")
    p.add_argument("--output", "-o", required=True, help="Output file path")
    p.add_argument("--entity-type", "-e", help="Filter by entity type")
    p.add_argument("--limit", "-n", type=int, default=10000, help="Max entries")

    # --- config ---
    p_cfg = sub.add_parser("config", help="View/edit configuration")
    sp = p_cfg.add_subparsers(dest="subcmd")

    sp.add_parser("show", help="Show current configuration")

    p = sp.add_parser("set", help="Set a config value")
    p.add_argument("key", help="Config key (dot-separated, e.g. 'report_author')")
    p.add_argument("value", help="Config value")

    p = sp.add_parser("get", help="Get a config value")
    p.add_argument("key", help="Config key")

    # --- db (database management) ---
    p_db = sub.add_parser("db", help="Database management — backup, restore, migrate")
    sp_db = p_db.add_subparsers(dest="subcmd")

    p = sp_db.add_parser("backup", help="Create a database backup")
    p.add_argument("--output", "-o", help="Output path (default: ~/.bbradar/backups/)")

    p = sp_db.add_parser("restore", help="Restore database from backup")
    p.add_argument("file", help="Path to backup .db file")

    sp_db.add_parser("migrate", help="Apply pending schema migrations")
    sp_db.add_parser("status", help="Show database version and stats")

    # --- h1 (HackerOne integration) ---
    p_h1 = sub.add_parser("h1", help="HackerOne API — programs, reports, earnings")
    sp_h1 = p_h1.add_subparsers(dest="subcmd")

    sp_h1.add_parser("auth", help="Configure HackerOne API credentials")
    sp_h1.add_parser("status", help="Check HackerOne connection status")

    p = sp_h1.add_parser("programs", help="List your HackerOne programs")
    p.add_argument("--bounties", action="store_true", default=False,
                   help="Only show programs that pay bounties")
    p.add_argument("--sort", choices=["name", "newest", "handle"], default="name",
                   help="Sort order (default: name)")
    p.add_argument("--search", "-s", default=None,
                   help="Filter by keyword in name or handle")
    p.add_argument("--state", default=None,
                   help="Filter by program state")
    p.add_argument("--refresh", action="store_true", default=False,
                   help="Force refresh from HackerOne API")

    p = sp_h1.add_parser("search", help="Search for bug bounty programs")
    p.add_argument("query", nargs="?", default=None, help="Search text")
    p.add_argument("--bounties-only", action="store_true", default=True,
                   help="Only show paid programs (default)")

    p = sp_h1.add_parser("import", help="Import a H1 program as a BBRadar project")
    p.add_argument("handle", help="HackerOne program handle (e.g. 'security')")

    p = sp_h1.add_parser("scope-sync", help="Sync scope from H1 into existing project")
    p.add_argument("project_id", nargs="?", type=int, default=None, help="BBRadar project ID (default: active project)")
    p.add_argument("handle", nargs="?", default=None, help="HackerOne program handle (default: from project)")

    p = sp_h1.add_parser("reports", help="List your submitted reports")
    p.add_argument("--state", "-s", help="Filter by state (new, triaged, resolved, etc.)")
    p.add_argument("--program", "-p", help="Filter by program handle")

    p = sp_h1.add_parser("report", help="Show details of a specific report")
    p.add_argument("report_id", help="HackerOne report ID")

    sp_h1.add_parser("balance", help="Show your current HackerOne balance")
    sp_h1.add_parser("earnings", help="Show earnings summary")

    p = sp_h1.add_parser("watch", help="Watch a H1 program for scope changes")
    p.add_argument("handle", nargs="?", default=None, help="HackerOne program handle (default: from active project)")

    p = sp_h1.add_parser("unwatch", help="Stop watching a program")
    p.add_argument("handle", nargs="?", default=None, help="HackerOne program handle (default: from active project)")

    sp_h1.add_parser("watchlist", help="List all watched programs")

    p = sp_h1.add_parser("check", help="Check watched programs for scope changes")
    p.add_argument("handle", nargs="?", default=None, help="Specific program handle (default: all)")
    p.add_argument("--auto-import", action="store_true", default=False,
                   help="Auto-import new scope into linked projects")
    p.add_argument("--new-programs", action="store_true", default=False,
                   help="Scan for newly launched H1 programs")

    p_notify = sp_h1.add_parser("notify", help="Configure notification channels")
    p_notify.add_argument("channel", nargs="?",
                          choices=["discord", "discord-scope", "discord-programs",
                                   "desktop", "status", "test"],
                          default="status", help="Channel to configure")
    p_notify.add_argument("value", nargs="?", default=None,
                          help="Webhook URL or enable/disable")

    p_mon = sp_h1.add_parser("monitor", help="Check watched programs for scope changes and scan for new programs")
    p_mon.add_argument("--auto-import", action="store_true", default=False,
                       help="Auto-import new scope into linked projects")
    p_mon.add_argument("--quiet", "-q", action="store_true", default=False,
                       help="Only output if there are changes (for cron)")

    p = sp_h1.add_parser("intel", help="Program intelligence — hacktivity, bounties, top vulns")
    p.add_argument("handle", nargs="?", default=None, help="HackerOne program handle (default: from active project)")
    p.add_argument("--refresh", action="store_true", default=False,
                   help="Force refresh from API (ignores cache)")

    p = sp_h1.add_parser("weaknesses", help="List accepted weakness types for a program")
    p.add_argument("handle", nargs="?", default=None, help="HackerOne program handle (default: from active project)")
    p.add_argument("--refresh", action="store_true", default=False,
                   help="Force refresh from API")

    # --- dashboard ---
    sub.add_parser("dashboard", help="Show combined BBRadar + HackerOne dashboard")

    return parser


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _resolve_project_id(args, attr="project_id"):
    """Resolve project ID from args or active project context."""
    # Check --project/-p flag first, then positional project_id
    flag_val = getattr(args, "project", None)
    if flag_val is not None:
        return flag_val
    val = getattr(args, attr, None)
    if val is not None:
        return val
    active = get_active_project()
    if active is not None:
        return active
    print("❌ No project ID given and no active project set. Run 'bb use <id>' or pass a project ID.",
          file=sys.stderr)
    sys.exit(1)


def _resolve_h1_handle(args):
    """Resolve HackerOne handle from args or active project's h1_handle."""
    handle = getattr(args, "handle", None)
    if handle:
        return handle
    active = get_active_project()
    if active is not None:
        p = projects.get_project(active)
        if p and p.get("h1_handle"):
            return p["h1_handle"]
    print("❌ No HackerOne handle given and active project has no linked H1 program.",
          file=sys.stderr)
    print("  Use 'bb h1 import <handle>' or pass a handle argument.", file=sys.stderr)
    sys.exit(1)


def _json_out(args, data):
    """Print data as JSON if --json flag is set. Returns True if handled."""
    if getattr(args, "json_output", False):
        print(json.dumps(data, indent=2, default=str))
        return True
    return False


# ═══════════════════════════════════════════════════════════════════
# Command Handlers
# ═══════════════════════════════════════════════════════════════════

def cmd_use(args):
    """Set or show the active project."""
    if args.clear:
        clear_active_project()
        print("✓ Active project cleared.")
        return
    if args.project_id is not None:
        p = projects.get_project(args.project_id)
        if not p:
            print(f"Project #{args.project_id} not found.", file=sys.stderr)
            sys.exit(1)
        set_active_project(args.project_id)
        print(f"✓ Active project: [{p['id']}] {p['name']}")
    else:
        active = get_active_project()
        if active:
            p = projects.get_project(active)
            if p:
                print(f"Active project: [{p['id']}] {p['name']}")
            else:
                print(f"Active project #{active} (project not found — run 'bb use --clear')")
        else:
            print("No active project set. Run 'bb use <project_id>'.")


def cmd_completion(args):
    """Generate shell tab-completion script."""
    commands = sorted(COMMAND_MAP.keys())
    cmds_str = " ".join(commands)

    if args.shell == "bash":
        print(textwrap.dedent(f"""\
            _bb_completions() {{
                local cur="${{COMP_WORDS[COMP_CWORD]}}"
                if [[ $COMP_CWORD -eq 1 ]]; then
                    COMPREPLY=( $(compgen -W "{cmds_str}" -- "$cur") )
                fi
            }}
            complete -F _bb_completions bb
        """))
    elif args.shell == "zsh":
        print(textwrap.dedent(f"""\
            #compdef bb
            _bb() {{
                local -a commands
                commands=({cmds_str})
                _describe 'command' commands
            }}
            compdef _bb bb
        """))
    elif args.shell == "fish":
        for cmd in commands:
            print(f"complete -c bb -n '__fish_use_subcommand' -a '{cmd}'")
    print(f"\n# Add to your shell config: eval \"$(bb completion {args.shell})\"")


def cmd_init(args):
    """Initialize BBRadar."""
    from .core.database import migrate_db
    print("🔧 Initializing BBRadar...")
    cfg = load_config()
    ensure_dirs(cfg)
    save_config(cfg)
    init_db()
    applied = migrate_db()
    print(f"  ✓ Database created at {get_db_path()}")
    if applied:
        for m in applied:
            print(f"  ✓ Migration: {m}")
    print(f"  ✓ Config saved to ~/.bbradar/config.yaml")
    print(f"  ✓ Data directories created")
    print("\n✅ BBRadar is ready. Run 'bb project create <name>' to start a new engagement.")


def cmd_status(args):
    """Show workspace status."""
    cfg = load_config()
    try:
        from .core.database import get_connection, get_schema_version, MIGRATIONS
        projs = projects.list_projects()
        active = [p for p in projs if p["status"] == "active"]
        all_vulns = vulns.list_vulns(limit=10000)
        vuln_stats = vulns.get_vuln_stats()
        active_pid = get_active_project()

        # Get last activity from audit log
        last_activity = None
        try:
            recent = get_audit_log(limit=1)
            if recent:
                last_activity = recent[0].get("timestamp")
        except Exception:
            pass

        # Check pending migrations
        pending_migrations = 0
        try:
            current_version = get_schema_version()
            if MIGRATIONS:
                latest = MIGRATIONS[-1][0]
                pending_migrations = max(0, latest - current_version)
        except Exception:
            pass

        status_data = {
            "projects_total": len(projs),
            "projects_active": len(active),
            "vuln_stats": vuln_stats,
            "active_project": active_pid,
            "data_dir": cfg["data_dir"],
            "last_activity": last_activity,
            "pending_migrations": pending_migrations,
        }
        if _json_out(args, status_data):
            return

        print("═══ BBRadar Status ═══\n")
        if active_pid:
            ap = projects.get_project(active_pid)
            name = ap["name"] if ap else "(unknown)"
            print(f"  Active:    [{active_pid}] {name}")
        print(f"  Projects:  {len(projs)} total, {len(active)} active")
        print(f"  Findings:  {vuln_stats['total']} total")
        for sev in ("critical", "high", "medium", "low"):
            count = vuln_stats["by_severity"].get(sev, 0)
            if count:
                print(f"    {severity_color(sev)}: {count}")
        if vuln_stats.get("total_bounty"):
            print(f"  Bounties:  ${vuln_stats['total_bounty']:.2f}")
        if last_activity:
            print(f"  Last activity: {last_activity}")
        print(f"\n  Data dir:  {cfg['data_dir']}")
        if pending_migrations:
            print(f"\n  ⚠ {pending_migrations} pending migration(s). Run 'bb db migrate'.")

        if active:
            print("\n  Active Projects:")
            for p in active[:5]:
                stats = projects.get_project_stats(p["id"])
                print(f"    [{p['id']}] {p['name']} — {stats['vulns_total']} vulns, {stats['targets']} targets")
    except Exception as e:
        print(f"  BBRadar not initialized. Run 'bb init' first.")


def cmd_project(args):
    if args.subcmd == "create":
        pid = projects.create_project(
            name=args.name, platform=args.platform,
            program_url=args.url, scope_raw=args.scope, rules=args.rules,
        )
        print(f"✓ Created project [{pid}] {args.name}")

    elif args.subcmd == "list":
        data = projects.list_projects(status=args.status)
        if _json_out(args, data):
            return
        if not data:
            print("No projects found.")
            return
        print(format_table(data, ["id", "name", "platform", "status", "created_at"]))

    elif args.subcmd == "show":
        p = projects.get_project(args.id)
        if not p:
            print(f"Project #{args.id} not found.")
            return
        stats = projects.get_project_stats(args.id)
        if _json_out(args, {"project": p, "stats": stats}):
            return
        print(f"\n═══ Project: {p['name']} ═══\n")
        for k, v in p.items():
            if v:
                print(f"  {k:15s}: {v}")
        stats = projects.get_project_stats(args.id)
        print(f"\n  --- Statistics ---")
        print(f"  Targets:          {stats['targets']}")
        print(f"  Findings:         {stats['vulns_total']}")
        print(f"  Recon data:       {stats['recon_data_points']}")
        print(f"  Notes:            {stats['notes']}")
        if stats["vulns_by_severity"]:
            print(f"  By severity:")
            for sev, cnt in stats["vulns_by_severity"].items():
                print(f"    {severity_color(sev)}: {cnt}")

    elif args.subcmd == "update":
        ok = projects.update_project(
            args.id, name=args.name, platform=args.platform,
            program_url=args.url, scope_raw=args.scope,
            rules=args.rules, status=args.status,
        )
        print(f"✓ Updated project #{args.id}" if ok else "No changes made.")

    elif args.subcmd == "delete":
        if confirm(f"Delete project #{args.id} and ALL related data?"):
            projects.delete_project(args.id)
            print(f"✓ Deleted project #{args.id}")

    elif args.subcmd == "stats":
        stats = projects.get_project_stats(args.id)
        print(json.dumps(stats, indent=2))

    else:
        print("Usage: bb project {create|list|show|update|delete|stats}")


def cmd_target(args):
    if args.subcmd == "add":
        pid = _resolve_project_id(args)
        if getattr(args, "stdin", False):
            count = 0
            for line in sys.stdin:
                val = line.strip()
                if val and not val.startswith("#"):
                    targets.add_target(pid, args.type, val,
                                       in_scope=not args.out_of_scope, tier=args.tier)
                    count += 1
            print(f"✓ Added {count} targets from stdin")
        else:
            if not args.value:
                print("❌ Provide a target value or use --stdin", file=sys.stderr)
                sys.exit(1)
            tid = targets.add_target(
                pid, args.type, args.value,
                in_scope=not args.out_of_scope, tier=args.tier, notes=args.notes,
            )
            print(f"✓ Added target [{tid}] {args.value}")

    elif args.subcmd == "list":
        pid = _resolve_project_id(args)
        in_scope = None
        if args.in_scope:
            in_scope = True
        elif args.out_of_scope:
            in_scope = False
        data = targets.list_targets(pid, asset_type=args.type, in_scope=in_scope)
        if _json_out(args, data):
            return
        if not data:
            print("No targets found.")
            return
        print(format_table(data, ["id", "asset_type", "value", "in_scope", "tier"]))

    elif args.subcmd == "import":
        pid = _resolve_project_id(args)
        count = targets.import_targets_from_file(
            pid, args.file, asset_type=args.type,
        )
        print(f"✓ Imported {count} targets")

    elif args.subcmd == "update":
        kwargs = {}
        if args.tier:
            kwargs["tier"] = args.tier
        if args.notes:
            kwargs["notes"] = args.notes
        if args.in_scope:
            kwargs["in_scope"] = True
        if args.out_of_scope:
            kwargs["in_scope"] = False
        ok = targets.update_target(args.id, **kwargs)
        print(f"✓ Updated target #{args.id}" if ok else "No changes made.")

    elif args.subcmd == "delete":
        if confirm(f"Delete target #{args.id} and its recon data?"):
            targets.delete_target(args.id)
            print(f"✓ Deleted target #{args.id}")

    else:
        print("Usage: bb target {add|list|import|update|delete}")


def cmd_recon(args):
    if args.subcmd == "add":
        if getattr(args, "stdin", False):
            count = recon.bulk_add_recon(
                args.target_id, args.data_type,
                [line.strip() for line in sys.stdin if line.strip()],
                source_tool=args.tool,
            )
            print(f"✓ Added {count} recon entries from stdin")
        else:
            if not args.value:
                print("❌ Provide a value or use --stdin", file=sys.stderr)
                sys.exit(1)
            rid = recon.add_recon(args.target_id, args.data_type, args.value, source_tool=args.tool)
            if rid:
                print(f"✓ Added recon [{rid}] {args.data_type}: {args.value}")
            else:
                print("Duplicate entry — already exists.")

    elif args.subcmd == "list":
        data = recon.list_recon(
            target_id=args.target, project_id=args.project,
            data_type=args.type, source_tool=args.tool, limit=args.limit,
        )
        if _json_out(args, data):
            return
        if not data:
            print("No recon data found.")
            return
        print(format_table(data, ["id", "target_id", "data_type", "value", "source_tool", "created_at"]))

    elif args.subcmd == "import":
        count = recon.ingest_from_file(args.target_id, args.file, args.data_type, source_tool=args.tool)
        print(f"✓ Imported {count} recon entries")

    elif args.subcmd == "summary":
        summary = recon.get_recon_summary(target_id=args.target, project_id=args.project)
        if not summary:
            print("No recon data found.")
            return
        print("\nRecon Data Summary:")
        total = 0
        for dtype, count in summary.items():
            print(f"  {dtype:20s}: {count}")
            total += count
        print(f"  {'TOTAL':20s}: {total}")

    elif args.subcmd == "export":
        path = recon.export_recon(
            target_id=args.target, project_id=args.project,
            data_type=args.type, output_path=args.output,
        )
        print(f"✓ Exported to {path}")

    elif args.subcmd == "run":
        tool = args.tool_name.lower()
        t = targets.get_target(args.target_id)
        if not t:
            print(f"Target #{args.target_id} not found.")
            return
        print(f"Running {tool} against {t['value']}...")
        try:
            if tool == "subfinder":
                count = recon.ingest_subfinder(args.target_id, t["value"], extra_args=args.args)
            elif tool == "nmap":
                count = recon.ingest_nmap(args.target_id, t["value"], extra_args=args.args or "-sV -sC")
            elif tool == "httpx":
                count = recon.ingest_httpx(args.target_id, targets=[t["value"]], extra_args=args.args)
            else:
                print(f"Tool '{tool}' not supported for auto-ingest. Use 'bb recon import' instead.")
                return
            print(f"✓ Ingested {count} results from {tool}")
        except RuntimeError as e:
            print(f"Error: {e}")

    else:
        print("Usage: bb recon {add|list|import|summary|export|run}")


def cmd_vuln(args):
    if args.subcmd == "create":
        pid = _resolve_project_id(args)
        vid = vulns.create_vuln(
            project_id=pid, title=args.title,
            severity=args.severity, vuln_type=args.type,
            target_id=args.target, description=args.description,
            impact=args.impact, reproduction=args.repro,
            request=args.request, response=args.response,
            remediation=args.remediation, cvss_score=args.cvss,
            cvss_vector=args.cvss_vector,
        )
        print(f"✓ Created finding [{vid}] {args.title} ({args.severity.upper()})")

    elif args.subcmd == "list":
        pid = getattr(args, "project", None) or get_active_project()
        data = vulns.list_vulns(
            project_id=pid, severity=args.severity,
            status=args.status, vuln_type=args.type,
        )
        if _json_out(args, data):
            return
        if not data:
            print("No findings.")
            return
        for v in data:
            v["severity"] = severity_color(v["severity"])
        print(format_table(data, ["id", "title", "severity", "vuln_type", "status"]))

    elif args.subcmd == "show":
        v = vulns.get_vuln(args.id)
        if not v:
            print(f"Finding #{args.id} not found.")
            return
        if _json_out(args, v):
            return
        print(f"\n═══ Finding: {v['title']} ═══\n")
        for k, val in v.items():
            if val and k not in ("request", "response"):
                label = k.replace("_", " ").title()
                print(f"  {label:20s}: {val}")
        if v.get("request"):
            print(f"\n  --- HTTP Request ---\n{v['request'][:500]}")
        if v.get("response"):
            print(f"\n  --- HTTP Response ---\n{v['response'][:500]}")

    elif args.subcmd == "update":
        kwargs = {}
        for field in ("severity", "status", "title", "description", "impact",
                       "remediation", "bounty", "report_url"):
            val = getattr(args, field.replace("-", "_"), None)
            if val is not None:
                key = "bounty_amount" if field == "bounty" else field
                kwargs[key] = val
        if args.type:
            kwargs["vuln_type"] = args.type
        if args.repro:
            kwargs["reproduction"] = args.repro
        if args.request:
            kwargs["request"] = args.request
        if args.response:
            kwargs["response"] = args.response
        ok = vulns.update_vuln(args.id, **kwargs)
        print(f"✓ Updated finding #{args.id}" if ok else "No changes made.")

    elif args.subcmd == "delete":
        if confirm(f"Delete finding #{args.id}?"):
            vulns.delete_vuln(args.id)
            print(f"✓ Deleted finding #{args.id}")

    elif args.subcmd == "evidence":
        ok = vulns.add_evidence(args.vuln_id, args.file)
        print(f"✓ Added evidence" if ok else "Already added or vuln not found.")

    elif args.subcmd == "stats":
        s = vulns.get_vuln_stats(project_id=args.project)
        print(f"\n═══ Vulnerability Statistics ═══\n")
        print(f"  Total: {s['total']}")
        if s.get("by_severity"):
            print("  By Severity:")
            for sev, cnt in s["by_severity"].items():
                print(f"    {severity_color(sev)}: {cnt}")
        if s.get("by_status"):
            print("  By Status:")
            for status, cnt in s["by_status"].items():
                print(f"    {status}: {cnt}")
        if s.get("total_bounty"):
            print(f"  Total Bounty: ${s['total_bounty']:.2f}")

    elif args.subcmd == "quick":
        pid = _resolve_project_id(args)
        vid = quick_vuln(
            template_key=args.template_key,
            project_id=pid,
            endpoint=args.endpoint,
            parameter=args.param or "",
            target=args.target or "",
            target_id=args.target_id,
            reproduction=args.repro,
            request=args.request,
        )
        tpl = vuln_templates.get_template(args.template_key)
        print(f"✓ Created finding [{vid}] from template '{args.template_key}' ({severity_color(tpl['severity'])})")

    elif args.subcmd == "transitions":
        v = vulns.get_vuln(args.id)
        if not v:
            print(f"Finding #{args.id} not found.")
            return
        allowed = vulns.get_allowed_transitions(args.id)
        print(f"  Current status: {v['status']}")
        if allowed:
            print(f"  Allowed transitions: {', '.join(allowed)}")
        else:
            print(f"  No transitions available (terminal state).")

    elif args.subcmd == "duplicates":
        v = vulns.get_vuln(args.id)
        if not v:
            print(f"Finding #{args.id} not found.")
            return
        dupes = vulns.find_duplicates(args.id)
        if not dupes:
            print(f"  No potential duplicates found for #{args.id}.")
            return
        print(f"\n  Potential duplicates of [{args.id}] {v['title']}:\n")
        for d in dupes:
            sev = severity_color(d["severity"])
            print(f"    [{d['id']}] {d['title'][:60]} ({sev}, project #{d['project_id']}, {d['status']})")
        print(f"\n  Use 'bb vuln merge <source_id> <target_id>' to merge.")

    elif args.subcmd == "merge":
        if confirm(f"Merge vuln #{args.source_id} into #{args.target_id}?"):
            ok = vulns.merge_vulns(args.source_id, args.target_id)
            if ok:
                print(f"✓ Merged #{args.source_id} → #{args.target_id}")
            else:
                print("Merge failed — check that both vulns exist.")

    else:
        print("Usage: bb vuln {create|list|show|update|delete|evidence|stats|quick|transitions|duplicates|merge}")


def cmd_note(args):
    if args.subcmd == "add":
        content = args.content
        if content == "-":
            content = sys.stdin.read()
        nid = notes.create_note(
            content=content, title=args.title,
            project_id=args.project, target_id=args.target,
            vuln_id=args.vuln, tags=args.tags,
        )
        print(f"✓ Added note [{nid}]")

    elif args.subcmd == "list":
        data = notes.list_notes(
            project_id=args.project, target_id=args.target,
            vuln_id=args.vuln, tag=args.tag, search=args.search,
        )
        if not data:
            print("No notes found.")
            return
        for n in data:
            n["content"] = n["content"][:60] + "..." if len(n["content"]) > 60 else n["content"]
        print(format_table(data, ["id", "title", "content", "tags", "created_at"]))

    elif args.subcmd == "show":
        n = notes.get_note(args.id)
        if not n:
            print(f"Note #{args.id} not found.")
            return
        print(f"\n═══ {n.get('title') or 'Note'} ═══")
        if n.get("tags"):
            print(f"Tags: {n['tags']}")
        print(f"Created: {n['created_at']}\n")
        print(n["content"])

    elif args.subcmd == "edit":
        ok = notes.update_note(
            args.id, content=args.content, title=args.title, tags=args.tags,
        )
        print(f"✓ Updated note #{args.id}" if ok else "No changes made.")

    elif args.subcmd == "delete":
        notes.delete_note(args.id)
        print(f"✓ Deleted note #{args.id}")

    elif args.subcmd == "export":
        path = notes.export_notes(project_id=args.project, output_path=args.output)
        if path:
            print(f"✓ Exported to {path}")
        else:
            print("No notes to export.")

    else:
        print("Usage: bb note {add|list|show|edit|delete|export}")


def cmd_report(args):
    if args.subcmd == "vuln":
        path = reports.generate_single_vuln_report(
            args.vuln_id, format=args.format, output_path=args.output,
        )
        print(f"✓ Report generated: {path}")

    elif args.subcmd == "full":
        pid = _resolve_project_id(args)
        path = reports.generate_full_report(
            pid, format=args.format, output_path=args.output,
        )
        print(f"✓ Report generated: {path}")

    elif args.subcmd == "executive":
        pid = _resolve_project_id(args)
        path = reports.generate_executive_summary(
            pid, format=args.format, output_path=args.output,
        )
        print(f"✓ Report generated: {path}")

    elif args.subcmd == "list":
        data = reports.list_reports(project_id=args.project)
        if not data:
            print("No reports generated yet.")
            return
        print(format_table(data, ["id", "project_id", "report_type", "format", "file_path", "created_at"]))

    else:
        print("Usage: bb report {vuln|full|executive|list}")


def cmd_kb(args):
    """Knowledge base commands."""
    if args.subcmd == "sync":
        sources = None if args.source == "all" else [args.source]
        print("\n═══ Knowledge Base Sync ═══\n")
        if args.force:
            print("  (--force: bypassing cache)\n")
        results = knowledgebase.sync_all(
            force=args.force, sources=sources, callback=print,
        )
        print("\n  --- Results ---")
        for r in results:
            status = r['status']
            icon = {"updated": "✓", "not_modified": "·", "unchanged": "·",
                    "skipped": "—", "error": "✗"}.get(status, "?")
            line = f"  {icon} {r['source']:8s}  {status:14s}  {r['records']} records"
            if r.get("reason"):
                line += f"  ({r['reason']})"
            print(line)
        print()

    elif args.subcmd == "status":
        rows = knowledgebase.get_sync_status()
        stats = knowledgebase.kb_stats()
        print("\n═══ Knowledge Base Status ═══\n")
        for r in rows:
            src = r['source']
            count = stats.get(src, 0)
            desc = r['description']
            last = r['last_sync']
            if last and last != 'never':
                last = last[:19].replace('T', ' ')
            print(f"  {src:8s}  {count:>6} records  last sync: {last}")
            print(f"           {desc}")
            print(f"           refresh interval: every {r['min_sync_hours']}h\n")

    elif args.subcmd == "search":
        results = knowledgebase.search_kb(args.query)
        total = sum(len(v) for v in results.values())
        if total == 0:
            print(f"No KB results for '{args.query}'.")
            return
        print(f"\n═══ KB Search: '{args.query}' ({total} results) ═══\n")
        if results["cwe"]:
            print("  CWE:")
            for r in results["cwe"]:
                desc = (r['description'] or '')[:70]
                print(f"    {r['cwe_id']:12s} {r['name'][:55]:55s} {desc}")
        if results["capec"]:
            print("\n  CAPEC:")
            for r in results["capec"]:
                sev = r.get('severity') or ''
                print(f"    {r['capec_id']:12s} {r['name'][:55]:55s} {sev}")
        if results["vrt"]:
            print("\n  VRT:")
            for r in results["vrt"]:
                pri = f"P{r['priority']}" if r.get('priority') else '  '
                print(f"    {pri}  {r['path'][:50]:50s}  {r['name']}")
        if results["nuclei"]:
            print("\n  Nuclei:")
            for r in results["nuclei"]:
                sev = (r.get('severity') or '')[:8]
                print(f"    {r['template_id'][:40]:40s} {sev:10s} {r['name'][:45]}")
        if results.get("cve"):
            print("\n  CVE:")
            for r in results["cve"]:
                score = r.get('cvss_v31_score') or ''
                sev = r.get('cvss_v31_severity') or ''
                desc = (r.get('description') or '')[:60]
                print(f"    {r['cve_id']:18s} {str(score):5s} {sev:10s} {desc}")
        if results.get("kev"):
            print("\n  KEV (actively exploited):")
            for r in results["kev"]:
                print(f"    {r['cve_id']:18s} {r.get('vendor',''):15s} {r.get('product',''):15s} {r.get('name','')[:40]}")
        print()

    elif args.subcmd == "cwe":
        cwe = knowledgebase.lookup_cwe(args.id)
        if not cwe:
            print(f"CWE '{args.id}' not found. Run 'bb kb sync --source cwe' first.")
            return
        print(f"\n═══ {cwe['cwe_id']}: {cwe['name']} ═══\n")
        print(f"  Abstraction: {cwe.get('abstraction', 'N/A')}")
        print(f"\n  Description:")
        print(textwrap.indent(textwrap.fill(cwe['description'] or '', 72), '    '))
        if cwe.get('extended_description'):
            print(f"\n  Extended Description:")
            print(textwrap.indent(textwrap.fill(cwe['extended_description'][:500], 72), '    '))
        if cwe.get('consequences'):
            print(f"\n  Consequences:")
            for c in cwe['consequences'][:5]:
                scopes = ', '.join(c.get('scope', []))
                impacts = ', '.join(c.get('impact', []))
                print(f"    [{scopes}] → {impacts}")
        if cwe.get('mitigations'):
            print(f"\n  Mitigations:")
            for m in cwe['mitigations'][:5]:
                phase = m.get('phase', '')
                desc = m.get('description', '')[:120]
                print(f"    [{phase}] {desc}")
        if cwe.get('owasp_mappings'):
            print(f"\n  OWASP Mappings:")
            for o in cwe['owasp_mappings']:
                print(f"    {o.get('taxonomy', '')} — {o.get('id', '')} {o.get('name', '')}")
        if cwe.get('capec_ids'):
            print(f"\n  Related CAPEC IDs: {', '.join(str(c) for c in cwe['capec_ids'][:15])}")
        if cwe.get('related_cwes'):
            rels = cwe['related_cwes'][:10]
            print(f"\n  Related CWEs:")
            for r in rels:
                print(f"    CWE-{r['cwe_id']} ({r['nature']})")
        print()

    elif args.subcmd == "capec":
        capec = knowledgebase.lookup_capec(args.id)
        if not capec:
            print(f"CAPEC '{args.id}' not found. Run 'bb kb sync --source capec' first.")
            return
        print(f"\n═══ {capec['capec_id']}: {capec['name']} ═══\n")
        if capec.get('likelihood'):
            print(f"  Likelihood: {capec['likelihood']}")
        if capec.get('severity'):
            print(f"  Severity:   {capec['severity']}")
        print(f"\n  Description:")
        print(textwrap.indent(textwrap.fill(capec['description'] or '', 72), '    '))
        if capec.get('prerequisites'):
            print(f"\n  Prerequisites:")
            for p in capec['prerequisites'][:5]:
                print(textwrap.indent(textwrap.fill(p[:200], 70), '    - '))
        if capec.get('mitigations'):
            print(f"\n  Mitigations:")
            for m in capec['mitigations'][:5]:
                print(textwrap.indent(textwrap.fill(m[:200], 70), '    - '))
        if capec.get('related_cwes'):
            print(f"\n  Related CWEs: {', '.join(capec['related_cwes'][:15])}")
        print()

    elif args.subcmd == "vrt":
        if args.category:
            rows = knowledgebase.browse_vrt(args.category)
        else:
            rows = knowledgebase.browse_vrt()
        if not rows:
            print("No VRT entries found. Run 'bb kb sync --source vrt' first.")
            return
        print(f"\n═══ Bugcrowd VRT ═══\n")
        for r in rows:
            pri = f"P{r['priority']}" if r.get('priority') else '  '
            depth = r['path'].count('.')
            indent = '  ' * depth
            print(f"  {pri}  {indent}{r['name']}  ({r['path']})")
        print(f"\n  Use 'bb kb vrt <category>' to drill into a category.")
        print(f"  Priority: P1=Critical  P2=High  P3=Medium  P4=Low  P5=Info")

    elif args.subcmd == "nuclei":
        results = knowledgebase.search_nuclei(
            query=args.query, severity=args.severity,
            cwe=args.cwe, tag=args.tag, limit=args.limit,
        )
        if not results:
            print("No nuclei templates found. Run 'bb kb sync --source nuclei' first.")
            return
        print(f"\n═══ Nuclei Templates ({len(results)} results) ═══\n")
        for r in results:
            sev = (r.get('severity') or 'unknown')[:8]
            cwe = r.get('cwe_id', '') or ''
            print(f"  {sev:10s} {r['template_id'][:40]:40s} {r['name'][:45]}")
            if cwe:
                print(f"             CWE: {cwe}")

    elif args.subcmd == "enrich":
        v = vulns.get_vuln(args.vuln_id)
        if not v:
            print(f"Finding #{args.vuln_id} not found.")
            return
        enrichment = knowledgebase.enrich_vuln(v)
        if not enrichment:
            print("No KB enrichment data found. Sync the KB first: bb kb sync")
            return
        print(f"\n═══ Enrichment for: {v['title']} ═══\n")
        if enrichment.get("cwe"):
            cwe = enrichment["cwe"]
            print(f"  CWE: {cwe['cwe_id']} — {cwe['name']}")
            if cwe.get('mitigations'):
                print(f"  Mitigations from CWE:")
                for m in cwe['mitigations'][:3]:
                    print(f"    [{m.get('phase', '')}] {m.get('description', '')[:100]}")
        if enrichment.get("related_capec"):
            print(f"\n  Related Attack Patterns:")
            for c in enrichment["related_capec"][:5]:
                print(f"    {c['capec_id']}: {c['name']} (Severity: {c.get('severity', 'N/A')})")
        if enrichment.get("related_nuclei"):
            print(f"\n  Related Nuclei Templates:")
            for n in enrichment["related_nuclei"][:5]:
                print(f"    {n['template_id']} ({n.get('severity', 'N/A')})")
        if enrichment.get("cve_details"):
            print(f"\n  CVE Intelligence:")
            for d in enrichment["cve_details"][:5]:
                exploited = "⚠ ACTIVELY EXPLOITED" if d.get("actively_exploited") else ""
                score = d.get('cvss_v31_score', 'N/A')
                print(f"    {d['cve_id']}  CVSS: {score}  {exploited}")
                if d.get("epss"):
                    epss = d["epss"]
                    pct = epss['epss_score'] * 100
                    print(f"      EPSS: {pct:.1f}% exploitation probability (top {epss['percentile']*100:.0f}%)")
        if enrichment.get("actively_exploited"):
            print(f"\n  ⚠  WARNING: This vulnerability is ACTIVELY EXPLOITED (CISA KEV)")
        print()

    elif args.subcmd == "cve":
        cve = knowledgebase.lookup_cve(args.id)
        if not cve:
            print(f"CVE '{args.id}' not found. Run 'bb kb sync --source cve' first.")
            return
        print(f"\n═══ {cve['cve_id']} ═══\n")
        if cve.get('description'):
            print(f"  Description:")
            print(textwrap.indent(textwrap.fill(cve['description'], 72), '    '))
        if cve.get('cvss_v31_score') is not None:
            print(f"\n  CVSS v3.1:  {cve['cvss_v31_score']} ({cve.get('cvss_v31_severity', 'N/A')})")
            if cve.get('cvss_v31_vector'):
                print(f"  Vector:     {cve['cvss_v31_vector']}")
        if cve.get('cwe_ids'):
            print(f"\n  CWE IDs: {', '.join(cve['cwe_ids'])}")
        if cve.get('published_at'):
            print(f"  Published:  {cve['published_at'][:19].replace('T', ' ')}")
        if cve.get('modified_at'):
            print(f"  Modified:   {cve['modified_at'][:19].replace('T', ' ')}")
        # KEV status
        if cve.get('actively_exploited'):
            kev = cve['kev']
            print(f"\n  ⚠  CISA KEV — ACTIVELY EXPLOITED")
            print(f"  Vendor:     {kev.get('vendor', '')}")
            print(f"  Product:    {kev.get('product', '')}")
            print(f"  Added:      {kev.get('date_added', '')}")
            print(f"  Due date:   {kev.get('due_date', '')}")
            if kev.get('required_action'):
                print(f"  Action:     {kev['required_action'][:120]}")
            if kev.get('known_ransomware') and kev['known_ransomware'].lower() != 'unknown':
                print(f"  Ransomware: {kev['known_ransomware']}")
        else:
            print(f"\n  KEV Status: Not in CISA KEV catalog")
        # EPSS
        if cve.get('epss'):
            epss = cve['epss']
            pct = epss['epss_score'] * 100
            print(f"\n  EPSS Score: {pct:.2f}% exploitation probability")
            print(f"  Percentile: top {epss['percentile']*100:.0f}%")
            if epss.get('score_date'):
                print(f"  Score date: {epss['score_date']}")
        # References
        if cve.get('references'):
            print(f"\n  References:")
            for ref in cve['references'][:10]:
                tags = ' '.join(f'[{t}]' for t in ref.get('tags', [])[:3])
                print(f"    {ref['url'][:80]} {tags}")
        # Affected products
        if cve.get('affected_products'):
            print(f"\n  Affected Products ({len(cve['affected_products'])}):")
            for p in cve['affected_products'][:10]:
                print(f"    {p}")
        print()

    elif args.subcmd == "kev":
        with knowledgebase.get_connection() as conn:
            if args.search:
                q = f"%{args.search}%"
                rows = conn.execute("""
                    SELECT cve_id, vendor, product, name, date_added, known_ransomware
                    FROM kb_kev
                    WHERE cve_id LIKE ? OR vendor LIKE ? OR product LIKE ?
                          OR name LIKE ? OR description LIKE ?
                    ORDER BY date_added DESC LIMIT ?
                """, (q, q, q, q, q, args.limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT cve_id, vendor, product, name, date_added, known_ransomware
                    FROM kb_kev ORDER BY date_added DESC LIMIT ?
                """, (args.limit,)).fetchall()

        if not rows:
            print("No KEV entries found. Run 'bb kb sync --source kev' first.")
            return

        print(f"\n═══ CISA KEV — Known Exploited Vulnerabilities ═══\n")
        for r in rows:
            ransomware = " 🔒" if r['known_ransomware'] and r['known_ransomware'].lower() not in ('unknown', '') else ""
            print(f"  {r['date_added']}  {r['cve_id']:18s} {r['vendor']:15s} {r['product']:15s} {r['name'][:35]}{ransomware}")
        total = conn.execute("SELECT COUNT(*) as c FROM kb_kev").fetchone()["c"]
        print(f"\n  Showing {len(rows)} of {total} entries (--limit to change)")
        print(f"  🔒 = used in ransomware campaigns")
        print(f"  Use 'bb kb cve <CVE-ID>' for full details")

    else:
        print("Usage: bb kb {sync|status|search|cwe|capec|vrt|nuclei|cve|kev|enrich}")
        print("\n  Sync the knowledge base first:  bb kb sync")
        print("  Then search or look up entries:  bb kb search xss")
        print("                                   bb kb cwe 79")
        print("                                   bb kb cve CVE-2024-1234")
        print("                                   bb kb kev")


def cmd_ingest(args):
    """Ingest tool output into a project."""
    from .modules.parsers import list_parsers as _lp

    if args.subcmd == "file":
        pid = _resolve_project_id(args)
        result = ingest.ingest_file(
            args.filepath, pid,
            tool_hint=args.tool, dry_run=args.dry_run,
            enrich=not args.no_enrich, min_severity=args.min_severity,
            scope_check=args.scope_check,
        )
        _print_ingest_result(result, args.dry_run)

    elif args.subcmd == "dir":
        pid = _resolve_project_id(args)
        results = ingest.ingest_directory(
            args.dirpath, pid,
            dry_run=args.dry_run, enrich=not args.no_enrich,
            min_severity=args.min_severity,
            scope_check=args.scope_check,
        )
        if not results:
            print("No recognizable tool output files found in directory.")
            return
        total_new = 0
        total_dup = 0
        total_created = 0
        for r in results:
            _print_ingest_result(r, args.dry_run, compact=True)
            total_new += r.get("new", 0)
            total_dup += r.get("duplicates", 0)
            total_created += len(r.get("created_ids", []))
        print(f"\n═══ Directory Summary ═══")
        print(f"  Files processed:  {len(results)}")
        print(f"  New findings:     {total_new}")
        print(f"  Duplicates:       {total_dup}")
        if not args.dry_run:
            print(f"  Vulns created:    {total_created}")

    elif args.subcmd == "pipe":
        pid = _resolve_project_id(args)
        result = ingest.ingest_stdin(
            pid, tool_hint=args.tool,
            dry_run=args.dry_run, enrich=not args.no_enrich,
            min_severity=args.min_severity,
            scope_check=args.scope_check,
        )
        _print_ingest_result(result, args.dry_run)

    elif args.subcmd == "tools":
        parsers = _lp()
        print(f"\n═══ Supported Tools ({len(parsers)}) ═══\n")
        for name in parsers:
            print(f"  - {name}")
        print(f"\n  Usage: bb ingest file <output_file> <project_id> [--tool <name>]")
        print(f"         <tool> | bb ingest pipe <project_id> --tool <name>")
        print(f"         bb ingest dir <directory> <project_id>")

    elif args.subcmd == "summary":
        pid = _resolve_project_id(args)
        summary = ingest.get_ingest_summary(pid)
        print(f"\n═══ Ingest Summary (Project #{pid}) ═══\n")
        print(f"  Total findings: {summary['total']}")
        if summary["by_severity"]:
            print("\n  By Severity:")
            for sev in ("critical", "high", "medium", "low", "informational"):
                cnt = summary["by_severity"].get(sev, 0)
                if cnt:
                    print(f"    {severity_color(sev)}: {cnt}")
        if summary["by_type"]:
            print("\n  By Type:")
            for vt, cnt in sorted(summary["by_type"].items(), key=lambda x: -x[1]):
                print(f"    {vt:25s}: {cnt}")
        if summary["by_tool"]:
            print("\n  By Source Tool:")
            for tool, cnt in sorted(summary["by_tool"].items(), key=lambda x: -x[1]):
                print(f"    {tool:15s}: {cnt}")

    else:
        print("Usage: bb ingest {file|dir|pipe|tools|summary}")
        print("\n  Ingest tool output to auto-create vulnerability findings.")
        print("  Supports: " + ", ".join(_lp()))
        print("\n  Examples:")
        print("    bb ingest file nuclei-results.json 1")
        print("    bb ingest dir ./scan-results/ 1")
        print("    nuclei -target example.com -json | bb ingest pipe 1 --tool nuclei")
        print("    bb ingest tools")


def _print_ingest_result(result: dict, dry_run: bool, compact: bool = False):
    """Print a single ingest result."""
    tool = result.get("tool", "unknown")
    filename = result.get("file", "")
    if isinstance(filename, str) and len(filename) > 60:
        filename = "..." + filename[-57:]

    if result.get("error"):
        print(f"  ✗ [{tool}] {filename}: {result['error']}")
        return

    total = result.get("total_parsed", 0)
    new = result.get("new", 0)
    dups = result.get("duplicates", 0)
    created = result.get("created_ids", [])

    if compact:
        action = f"created {len(created)} vulns" if not dry_run else f"{new} new"
        print(f"  {'→' if dry_run else '✓'} [{tool}] {filename}: {total} parsed, {new} new, {dups} dups" +
              (f", {action}" if not dry_run else ""))
        return

    label = "DRY RUN" if dry_run else "Ingest"
    print(f"\n═══ {label}: {tool} ═══\n")
    print(f"  File:       {filename}")
    print(f"  Parsed:     {total} findings")
    print(f"  New:        {new}")
    print(f"  Duplicates: {dups}")
    if result.get("skipped"):
        print(f"  Skipped:    {result['skipped']} (below min severity)")
    if result.get("out_of_scope"):
        print(f"  Out-of-scope: {result['out_of_scope']} (filtered by scope rules)")

    if not dry_run and created:
        print(f"  Created:    {len(created)} draft vulns (IDs: {', '.join(str(i) for i in created[:20])})")
        if result.get("create_errors"):
            print(f"  ⚠ Failed:   {len(result['create_errors'])} finding(s) could not be created:")
            for err in result["create_errors"][:5]:
                print(f"    {err}")
    elif dry_run and result.get("findings"):
        print(f"\n  --- Findings Preview ---")
        for f in result["findings"][:15]:
            sev = severity_color(f.get("severity", "info"))
            print(f"    [{sev}] {f.get('title', 'Untitled')[:70]}")
            if f.get("endpoint"):
                print(f"           → {f['endpoint'][:70]}")
        if len(result["findings"]) > 15:
            print(f"    ... and {len(result['findings']) - 15} more")


def cmd_scope(args):
    """Manage scope rules."""
    if args.subcmd == "add":
        pid = _resolve_project_id(args)
        # Auto-detect exclude from ! prefix
        pattern = args.pattern
        rule_type = args.type
        if pattern.startswith("!"):
            pattern = pattern[1:].strip()
            rule_type = "exclude"

        rid = scope.add_rule(
            pid, pattern, rule_type=rule_type,
            pattern_type=args.pattern_type, asset_category=args.category,
            priority=args.priority, notes=args.notes,
        )
        icon = "✓" if rule_type == "include" else "✗"
        print(f"{icon} Added {rule_type} rule [{rid}]: {pattern}")

    elif args.subcmd == "exclude":
        pid = _resolve_project_id(args)
        rid = scope.add_rule(
            pid, args.pattern, rule_type="exclude",
            priority=args.priority, notes=args.notes,
        )
        print(f"✗ Added exclude rule [{rid}]: {args.pattern}")

    elif args.subcmd == "list":
        pid = _resolve_project_id(args)
        rules = scope.list_rules(pid)
        if not rules:
            print("No scope rules defined. Use 'bb scope add' or 'bb scope import'.")
            return
        print(f"\n═══ Scope Rules (Project #{pid}) ═══\n")
        for r in rules:
            icon = "✓" if r["rule_type"] == "include" else "✗"
            ptype = r["pattern_type"][:4]
            cat = r.get("asset_category") or "any"
            pri = f"P{r['priority']}" if r["priority"] else ""
            notes = f"  — {r['notes']}" if r.get("notes") else ""
            print(f"  [{r['id']:3d}] {icon} {r['rule_type']:7s}  {ptype:5s}  {r['pattern']:40s}  {cat:8s}  {pri}{notes}")
        print(f"\n  Total: {len(rules)} rules "
              f"({sum(1 for r in rules if r['rule_type'] == 'include')} includes, "
              f"{sum(1 for r in rules if r['rule_type'] == 'exclude')} excludes)")

    elif args.subcmd == "delete":
        rule = scope.get_rule(args.rule_id)
        if not rule:
            print(f"Rule #{args.rule_id} not found.")
            return
        scope.delete_rule(args.rule_id)
        print(f"✓ Deleted rule #{args.rule_id}: {rule['rule_type']} {rule['pattern']}")

    elif args.subcmd == "clear":
        pid = _resolve_project_id(args)
        if confirm(f"Remove ALL scope rules for project #{pid}?"):
            count = scope.clear_rules(pid)
            print(f"✓ Removed {count} scope rules")

    elif args.subcmd == "check":
        pid = _resolve_project_id(args)
        result = scope.check_scope(pid, args.value)
        if result["in_scope"] is None:
            print(f"  ? {args.value}  — {result['reason']}")
        elif result["in_scope"]:
            print(f"  ✓ IN SCOPE:  {args.value}")
            matched = result.get("matched_rule")
            if matched:
                print(f"    Matched:  rule #{matched['id']} — {matched['rule_type']} {matched['pattern_type']}: {matched['pattern']}")
                if matched.get("notes"):
                    print(f"    Notes:    {matched['notes']}")
            else:
                print(f"    Reason:   {result['reason']}")
        else:
            print(f"  ✗ OUT OF SCOPE:  {args.value}")
            matched = result.get("matched_rule")
            if matched:
                print(f"    Blocked:  rule #{matched['id']} — {matched['rule_type']} {matched['pattern_type']}: {matched['pattern']}")
                if matched.get("notes"):
                    print(f"    Notes:    {matched['notes']}")
            else:
                print(f"    Reason:   {result['reason']}")
        if result.get("all_matches") and len(result["all_matches"]) > 1:
            print(f"    All matching rules ({len(result['all_matches'])}):")
            for m in result["all_matches"]:
                icon = "✓" if m["rule_type"] == "include" else "✗"
                print(f"      {icon} #{m['id']} {m['rule_type']:7s} {m['pattern']}  (priority {m['priority']})")

    elif args.subcmd == "check-file":
        from pathlib import Path
        p = Path(args.file)
        if not p.exists():
            print(f"File not found: {args.file}")
            return
        pid = _resolve_project_id(args)
        values = [l.strip() for l in p.read_text().splitlines()
                  if l.strip() and not l.strip().startswith("#")]
        results = scope.check_scope_batch(pid, values)
        in_count = 0
        out_count = 0
        unknown = 0
        for r in results:
            if r["in_scope"] is None:
                icon = "?"
                unknown += 1
            elif r["in_scope"]:
                icon = "✓"
                in_count += 1
            else:
                icon = "✗"
                out_count += 1
            print(f"  {icon} {r['value']:50s}  {r['reason']}")
        print(f"\n  Summary: {in_count} in-scope, {out_count} out-of-scope, {unknown} unknown")

    elif args.subcmd == "import":
        pid = _resolve_project_id(args)
        result = scope.import_from_file(pid, args.file)
        if result.get("error"):
            print(f"  ✗ Import error: {result['error']}")
        else:
            src = result.get("source", "text")
            print(f"✓ Imported {result.get('added', 0)} scope rules (format: {src})")
            if result.get("skipped_count"):
                print(f"  ⚠ {result['skipped_count']} line(s) could not be parsed:")
                for line_num, line_text in result.get("skipped", [])[:5]:
                    print(f"    line {line_num}: {line_text[:70]}")

    elif args.subcmd == "validate":
        pid = _resolve_project_id(args)
        if args.fix:
            result = scope.auto_scope_targets(pid, dry_run=False)
            print(f"\n═══ Scope Validation + Fix ═══\n")
            print(f"  Total targets: {result['total_targets']}")
            print(f"  Already correct: {result['correct']}")
            if result["changes"]:
                print(f"  Fixed: {len(result['changes'])}")
                for c in result["changes"]:
                    old = "in-scope" if c["old_scope"] else "out-of-scope"
                    new = "in-scope" if c["new_scope"] else "out-of-scope"
                    print(f"    [{c['target_id']}] {c['value']}: {old} → {new}  ({c['reason']})")
            if result["unmatched"]:
                print(f"  Unmatched (no rule): {result['unmatched']}")
        else:
            result = scope.validate_targets(pid)
            if result.get("message"):
                print(f"  {result['message']}")
                return
            print(f"\n═══ Scope Validation ═══\n")
            print(f"  Total targets: {result['total']}")
            print(f"  Correct: {result['correct']}")
            if result["mismatches"]:
                print(f"  Mismatches: {len(result['mismatches'])}")
                for m in result["mismatches"]:
                    t = m["target"]
                    cur = "in-scope" if m["current"] else "out-of-scope"
                    exp = "in-scope" if m["expected"] else "out-of-scope"
                    print(f"    [{t['id']}] {t['value']}: currently {cur}, should be {exp}")
                    print(f"         Reason: {m['reason']}")
                print(f"\n  Run 'bb scope validate {pid} --fix' to auto-correct.")
            else:
                print(f"  All targets match scope rules. ✓")
            if result["unmatched"]:
                print(f"  Unmatched (no rule applies): {len(result['unmatched'])}")
                for t in result["unmatched"][:10]:
                    print(f"    [{t['id']}] {t['value']}")

    elif args.subcmd == "overview":
        pid = _resolve_project_id(args)
        ov = scope.scope_overview(pid)
        print(f"\n═══ Scope Overview (Project #{pid}) ═══\n")
        print(f"  Rules: {ov['rules_total']} ({len(ov['includes'])} includes, {len(ov['excludes'])} excludes)")
        print(f"  Targets: {ov['targets_total']} ({ov['targets_in_scope']} in-scope, {ov['targets_out_scope']} out-of-scope)")

        if ov["includes"]:
            print(f"\n  In-Scope Patterns:")
            for r in ov["includes"]:
                notes = f"  — {r['notes']}" if r.get("notes") else ""
                print(f"    ✓ {r['pattern']}{notes}")

        if ov["excludes"]:
            print(f"\n  Exclusions:")
            for r in ov["excludes"]:
                notes = f"  — {r['notes']}" if r.get("notes") else ""
                print(f"    ✗ {r['pattern']}{notes}")

        if ov["in_scope_targets"]:
            print(f"\n  In-Scope Targets ({ov['targets_in_scope']}):")
            for t in ov["in_scope_targets"][:20]:
                print(f"    [{t['id']}] {t['asset_type']:8s} {t['value']}")
            if ov["targets_in_scope"] > 20:
                print(f"    ... and {ov['targets_in_scope'] - 20} more")

        if ov["out_scope_targets"]:
            print(f"\n  Out-of-Scope Targets ({ov['targets_out_scope']}):")
            for t in ov["out_scope_targets"][:10]:
                print(f"    [{t['id']}] {t['asset_type']:8s} {t['value']}")

    elif args.subcmd == "wizard":
        _scope_wizard()

    else:
        print("Usage: bb scope {add|exclude|list|delete|clear|check|check-file|import|validate|overview|wizard}")
        print("\n  Define scope rules, then check targets against them.")
        print("\n  Quick start:")
        print("    bb scope add 1 '*.example.com'            # include wildcard")
        print("    bb scope exclude 1 'admin.example.com'     # exclude specific host")
        print("    bb scope add 1 '10.0.0.0/24'              # include CIDR range")
        print("    bb scope check 1 sub.example.com           # check a value")
        print("    bb scope import 1 scope.txt                # import from file")
        print("    bb scope validate 1 --fix                  # sync targets to rules")


def _scope_wizard():
    """Interactive scope definition wizard."""
    print("\n═══ Scope Definition Wizard ═══\n")

    # Get project
    from .modules import projects as proj_mod
    projs = proj_mod.list_projects(status="active")
    if not projs:
        print("No active projects. Create one first: bb project create <name>")
        return

    print("  Active projects:")
    for p in projs:
        existing = scope.list_rules(p["id"])
        rule_count = f" ({len(existing)} rules)" if existing else ""
        print(f"    [{p['id']}] {p['name']}{rule_count}")

    try:
        pid = int(input("\n  Project ID: ").strip())
    except (ValueError, EOFError):
        print("Cancelled.")
        return

    # Check for existing rules
    existing = scope.list_rules(pid)
    if existing:
        print(f"\n  Project already has {len(existing)} scope rules.")
        action = input("  (a)dd more, (c)lear and start fresh, or (q)uit? [a]: ").strip().lower()
        if action == "c":
            scope.clear_rules(pid)
            print("  Cleared existing rules.")
        elif action == "q":
            return

    print("\n  Enter scope rules one per line.")
    print("  Prefix with ! or - to mark as exclusion.")
    print("  Use labels like 'IN: ...' or 'OUT: ...'")
    print("  Supports: wildcards (*.example.com), CIDR (10.0.0.0/24), exact, regex")
    print("  Enter a blank line when done.\n")

    lines = []
    while True:
        try:
            line = input("  > ").strip()
        except EOFError:
            break
        if not line:
            break
        lines.append(line)

    if not lines:
        print("  No rules entered.")
        return

    text = "\n".join(lines)
    result = scope.import_from_text(pid, text, source="wizard")
    added = result.get("added", 0)
    print(f"\n  ✓ Added {added} scope rules.")

    # Offer to validate existing targets
    from .modules import targets as tgt_mod
    tgt_count = len(tgt_mod.list_targets(pid))
    if tgt_count > 0:
        do_validate = input(f"\n  Validate {tgt_count} existing targets against new rules? [Y/n]: ").strip().lower()
        if do_validate != "n":
            val_result = scope.auto_scope_targets(pid, dry_run=False)
            if val_result["changes"]:
                print(f"  ✓ Updated {len(val_result['changes'])} target(s):")
                for c in val_result["changes"]:
                    new_label = "in-scope" if c["new_scope"] else "out-of-scope"
                    print(f"    {c['value']} → {new_label}")
            else:
                print(f"  ✓ All targets already match scope rules.")

    # Show overview
    print()
    ov = scope.scope_overview(pid)
    print(f"  Rules: {ov['rules_total']} ({len(ov['includes'])} includes, {len(ov['excludes'])} excludes)")
    print(f"  Targets: {ov['targets_in_scope']} in-scope, {ov['targets_out_scope']} out-of-scope")


def cmd_wizard(args):
    """Interactive wizards."""
    if args.subcmd == "project":
        pid = wizard_project()
        print(f"\n✓ Wizard complete — project [{pid}] created.")

    elif args.subcmd == "target":
        tid = wizard_target()
        print(f"\n✓ Wizard complete — target [{tid}] added.")

    elif args.subcmd == "vuln":
        vid = wizard_vuln()
        print(f"\n✓ Wizard complete — finding [{vid}] logged.")

    else:
        print("Usage: bb wizard {project|target|vuln}")
        print("\n  Interactive guided flows that walk you through each step.")
        print("  The vuln wizard includes a template picker so you don't")
        print("  need to type descriptions, impact, or remediation by hand.")


def cmd_templates(args):
    """Browse / search the vulnerability knowledge base."""
    if args.subcmd == "list":
        keys = vuln_templates.list_template_keys()
        print(f"\n═══ Vulnerability Templates ({len(keys)}) ═══\n")
        for key in keys:
            t = vuln_templates.get_template(key)
            print(f"  {key:30s} {severity_color(t['severity']):12s}  {t['cwe']}  {t['owasp']}")
        print(f"\n  Use 'bb templates show <key>' for full details.")
        print(f"  Use 'bb vuln quick <key> <project_id> <endpoint>' to log a finding fast.")

    elif args.subcmd == "show":
        t = vuln_templates.get_template(args.key)
        if not t:
            print(f"Template '{args.key}' not found. Run 'bb templates list'.")
            return
        print(f"\n═══ Template: {t['key']} ═══\n")
        print(f"  Title:        {t['title']}")
        print(f"  Type:         {t['vuln_type']}")
        print(f"  Severity:     {severity_color(t['severity'])}")
        print(f"  CVSS:         {t['cvss_score']}  {t['cvss_vector']}")
        print(f"  CWE:          {t['cwe']}")
        print(f"  OWASP:        {t['owasp']}")
        print(f"\n  Description:")
        print(textwrap.indent(textwrap.fill(t['description'], 72), '    '))
        print(f"\n  Impact:")
        print(textwrap.indent(textwrap.fill(t['impact'], 72), '    '))
        print(f"\n  Remediation:")
        print(textwrap.indent(textwrap.fill(t['remediation'], 72), '    '))
        if t.get('references'):
            print(f"\n  References:")
            for ref in t['references']:
                print(f"    - {ref}")

    elif args.subcmd == "search":
        results = vuln_templates.search_templates(args.query)
        if not results:
            print(f"No templates matching '{args.query}'.")
            return
        print(f"\n  Found {len(results)} template(s) matching '{args.query}':\n")
        for t in results:
            print(f"  {t['key']:30s} {severity_color(t['severity']):12s}  {t['cwe']}")

    elif args.subcmd == "categories":
        groups = vuln_templates.get_templates_by_category()
        for cat, tmpls in sorted(groups.items()):
            print(f"\n  {cat}")
            for t in tmpls:
                print(f"    {t['key']:30s} {severity_color(t['severity'])}")

    else:
        print("Usage: bb templates {list|show|search|categories}")


def cmd_workflow(args):
    if args.subcmd == "list":
        wfs = workflows.list_workflows()
        if not wfs:
            print("No workflows found.")
            return
        print(format_table(wfs, ["name", "description", "steps"]))

    elif args.subcmd == "run":
        print(f"Starting workflow '{args.name}'...")
        result = workflows.run_workflow(
            args.name, args.target_id,
            project_id=args.project, dry_run=args.dry_run,
        )
        print(result["output"])
        print(f"\n═══ Summary ═══")
        print(f"  Steps run:     {result['steps_run']}")
        print(f"  Steps OK:      {result['steps_ok']}")
        print(f"  Steps failed:  {result['steps_failed']}")
        print(f"  Data ingested: {result['data_ingested']}")
        if result.get("run_id"):
            print(f"  Run ID:        {result['run_id']}")

    elif args.subcmd == "show":
        run = workflows.get_workflow_run(args.run_id)
        if not run:
            print(f"Workflow run #{args.run_id} not found.")
            return
        print(f"\n═══ Workflow Run #{run['id']} ═══")
        print(f"  Workflow:   {run['workflow_name']}")
        print(f"  Status:     {run['status']}")
        print(f"  Started:    {run['started_at']}")
        print(f"  Finished:   {run.get('finished_at', 'still running')}")
        if run.get("output_log"):
            print(f"\n--- Output ---\n{run['output_log']}")

    elif args.subcmd == "history":
        runs = workflows.list_workflow_runs(
            project_id=args.project, target_id=args.target,
        )
        if not runs:
            print("No workflow runs found.")
            return
        print(format_table(runs, ["id", "workflow_name", "target_id", "status", "started_at"]))

    elif args.subcmd == "preflight":
        result = workflows.preflight_check(args.name)
        if result["ok"]:
            print(f"✓ All {result['steps']} tools available for workflow '{args.name}'.")
        else:
            print(f"✗ Missing tools for workflow '{args.name}':")
            for tool in result["missing"]:
                print(f"    ✗ {tool}")
            print(f"\n  Install missing tools before running this workflow.")

    else:
        print("Usage: bb workflow {list|run|show|history|preflight}")


def cmd_audit(args):
    from .core.audit import get_audit_stats, purge_audit_log, export_audit_log

    if args.subcmd == "log" or args.subcmd is None:
        entity_type = getattr(args, "entity_type", None)
        entity_id = getattr(args, "entity_id", None)
        limit = getattr(args, "limit", 30)
        entries = get_audit_log(
            entity_type=entity_type, entity_id=entity_id,
            limit=limit,
        )
        if not entries:
            print("No audit log entries.")
            return
        print(format_table(entries, ["id", "timestamp", "action", "entity_type", "entity_id", "details"]))

    elif args.subcmd == "stats":
        s = get_audit_stats()
        print(f"\n═══ Audit Log Statistics ═══\n")
        print(f"  Total entries: {s['total']}")
        print(f"  Oldest entry:  {s['oldest'] or 'N/A'}")
        if s["by_action"]:
            print(f"\n  By Action:")
            for action, cnt in s["by_action"].items():
                print(f"    {action:20s}: {cnt}")

    elif args.subcmd == "purge":
        days = args.days
        if confirm(f"Purge audit log entries older than {days} days?"):
            deleted = purge_audit_log(days=days)
            print(f"✓ Purged {deleted} audit log entries.")

    elif args.subcmd == "export":
        path = export_audit_log(
            output_path=args.output,
            entity_type=getattr(args, "entity_type", None),
            limit=args.limit,
        )
        print(f"✓ Exported audit log to {path}")

    else:
        print("Usage: bb audit {log|stats|purge|export}")


def cmd_config(args):
    if args.subcmd == "show":
        cfg = load_config()
        print(json.dumps(cfg, indent=2))

    elif args.subcmd == "set":
        cfg = set_config_value(args.key, args.value)
        print(f"✓ Set {args.key} = {args.value}")

    elif args.subcmd == "get":
        val = get_config_value(args.key)
        print(f"{args.key} = {val}")

    else:
        print("Usage: bb config {show|set|get}")


def cmd_db(args):
    """Database management — backup, restore, migrate."""
    from .core.database import backup_db, restore_db, migrate_db, get_schema_version, get_db_path

    if args.subcmd == "backup":
        path = backup_db(output_path=args.output)
        size_kb = os.path.getsize(path) / 1024
        print(f"✓ Backup created: {path} ({size_kb:.1f} KB)")

    elif args.subcmd == "restore":
        if confirm(f"Restore database from {args.file}? Current DB will be saved as .pre-restore"):
            dest = restore_db(args.file)
            print(f"✓ Database restored to {dest}")
            print("  Previous DB saved as bbradar.db.pre-restore")

    elif args.subcmd == "migrate":
        applied = migrate_db()
        if applied:
            print(f"✓ Applied {len(applied)} migration(s):")
            for m in applied:
                print(f"    {m}")
        else:
            print("✓ Database is up to date — no migrations needed.")

    elif args.subcmd == "status":
        db_path = get_db_path()
        if not db_path.exists():
            print("No database found. Run 'bb init' first.")
            return
        version = get_schema_version()
        size_kb = os.path.getsize(db_path) / 1024
        print(f"\n═══ Database Status ═══\n")
        print(f"  Path:     {db_path}")
        print(f"  Size:     {size_kb:.1f} KB")
        print(f"  Version:  {version}")
        # Count records
        from .core.database import get_connection
        with get_connection() as conn:
            tables = ["projects", "targets", "recon_data", "vulns", "notes",
                       "scope_rules", "audit_log", "workflow_runs", "reports"]
            for t in tables:
                try:
                    cnt = conn.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
                    if cnt:
                        print(f"  {t:15s}: {cnt} records")
                except Exception:
                    pass

    else:
        print("Usage: bb db {backup|restore|migrate|status}")


# ═══════════════════════════════════════════════════════════════════
# Evidence Handler
# ═══════════════════════════════════════════════════════════════════

def cmd_evidence(args):
    """Evidence file management."""
    from .modules.evidence import get_evidence_stats, find_orphaned_files, cleanup_orphans

    if args.subcmd == "stats":
        s = get_evidence_stats()
        print(f"\n═══ Evidence Statistics ═══\n")
        print(f"  Total files:      {s['total_files']}")
        print(f"  Total size:       {s['total_size'] / 1024 / 1024:.1f} MB")
        print(f"  Referenced:       {s['referenced']}")
        print(f"  Orphaned:         {s['orphaned']}")
        if s.get("orphan_size"):
            print(f"  Orphan size:      {s['orphan_size'] / 1024 / 1024:.1f} MB")

    elif args.subcmd == "orphans":
        orphans = find_orphaned_files()
        if not orphans:
            print("No orphaned evidence files found.")
            return
        print(f"\n  Orphaned evidence files ({len(orphans)}):\n")
        for o in orphans:
            size_kb = o["size"] / 1024
            print(f"    {o['relative']:50s}  {size_kb:.1f} KB")
        total = sum(o["size"] for o in orphans) / 1024 / 1024
        print(f"\n  Total: {len(orphans)} files, {total:.1f} MB")
        print(f"  Run 'bb evidence cleanup --execute' to remove them.")

    elif args.subcmd == "cleanup":
        dry_run = not args.execute
        result = cleanup_orphans(dry_run=dry_run)
        if result["orphans_found"] == 0:
            print("No orphaned files found.")
            return
        if dry_run:
            print(f"\n  DRY RUN — would remove {result['orphans_found']} files "
                  f"({result['total_size'] / 1024 / 1024:.1f} MB)")
            for f in result["files"]:
                print(f"    {f['relative']}")
            print(f"\n  Add --execute to actually delete them.")
        else:
            print(f"✓ Removed {result['removed']} orphaned files "
                  f"({result['total_size'] / 1024 / 1024:.1f} MB freed)")

    else:
        print("Usage: bb evidence {stats|orphans|cleanup}")


# ═══════════════════════════════════════════════════════════════════
# HackerOne Integration
# ═══════════════════════════════════════════════════════════════════

def cmd_h1(args):
    """HackerOne API integration."""
    import getpass

    if args.subcmd == "auth":
        print("\n═══ HackerOne API Setup ═══\n")
        print("  Get your API token at: https://hackerone.com/settings/api_token\n")
        username = input("  API Username (identifier): ").strip()
        if not username:
            print("  Cancelled.")
            return
        token = getpass.getpass("  API Token: ").strip()
        if not token:
            print("  Cancelled.")
            return

        print("  Verifying credentials...")
        hackerone.configure_auth(username, token)
        print(f"\n  ✓ Authenticated as '{username}'. Credentials saved.")
        print(f"  Try: bb h1 programs\n")

    elif args.subcmd == "status":
        status = hackerone.check_auth()
        if not status["configured"]:
            print("\n  HackerOne: not configured. Run 'bb h1 auth' to connect.\n")
        elif status["valid"]:
            print(f"\n  HackerOne: ✓ connected as '{status['username']}'\n")
        else:
            print(f"\n  HackerOne: ✗ credentials invalid (username: {status['username']})")
            print(f"  Run 'bb h1 auth' to reconfigure.\n")

    elif args.subcmd == "programs":
        result = hackerone.get_cached_programs(
            bounties_only=args.bounties,
            sort=args.sort,
            search=args.search,
            state=args.state,
            refresh=args.refresh,
        )
        progs = result["programs"]
        if not progs:
            print("No programs found matching your filters.")
            return
        source = "cache" if result["from_cache"] else "API"
        filter_note = ""
        if result["filtered"] < result["total"]:
            filter_note = f" (filtered from {result['total']})"
        print(f"\n  HackerOne Programs ({result['filtered']}{filter_note}) [{source}]:\n")
        rows = []
        for p in progs:
            bounty = "💰" if p["offers_bounties"] else "  "
            rows.append({"handle": p["handle"], "name": p["name"][:40], "bounty": bounty, "state": p["state"]})
        print(format_table(rows, ["handle", "name", "bounty", "state"]))

    elif args.subcmd == "search":
        progs = hackerone.search_programs(
            query=args.query,
            bounties_only=args.bounties_only,
        )
        if not progs:
            print("No programs found matching your search.")
            return
        print(f"\n  Programs Found ({len(progs)}):\n")
        rows = []
        for p in progs:
            bounty = "💰" if p["offers_bounties"] else "  "
            sub = p.get("submission_state", "")
            rows.append({"handle": p["handle"], "name": p["name"][:40], "bounty": bounty, "submissions": sub})
        print(format_table(rows, ["handle", "name", "bounty", "submissions"]))
        print(f"\n  Import a program: bb h1 import <handle>\n")

    elif args.subcmd == "import":
        print(f"  Importing program '{args.handle}' from HackerOne...")
        result = hackerone.import_program(args.handle)
        print(f"\n  ✓ Created project [{result['project_id']}]")
        print(f"    Targets imported: {result['targets_added']}")
        print(f"    Scope rules:     {result['scope_rules_added']}")
        print(f"\n  Next steps:")
        print(f"    bb project show {result['project_id']}")
        print(f"    bb scope list {result['project_id']}")
        print(f"    bb recon run {result['project_id']}\n")

    elif args.subcmd == "scope-sync":
        pid = _resolve_project_id(args)
        handle = _resolve_h1_handle(args)
        result = hackerone.sync_scope(pid, handle)
        print(f"\n  ✓ Scope synced from '{handle}'")
        print(f"    New targets: {result['new_targets']}")
        print(f"    New rules:   {result['new_rules']}\n")

    elif args.subcmd == "reports":
        h1_reports = hackerone.list_reports(
            state=getattr(args, "state", None),
            program=getattr(args, "program", None),
        )
        if not h1_reports:
            print("No reports found.")
            return
        print(f"\n  Your HackerOne Reports ({len(h1_reports)}):\n")
        rows = []
        for r in h1_reports:
            sev = r.get("severity_rating", "-")
            rows.append({"id": r["id"], "title": r["title"][:50], "state": r["state"], "severity": sev, "date": r["created_at"][:10]})
        print(format_table(rows, ["id", "title", "state", "severity", "date"]))

    elif args.subcmd == "report":
        r = hackerone.get_report(args.report_id)
        print(f"\n═══ Report #{r['id']} ═══\n")
        print(f"  Title:    {r['title']}")
        print(f"  State:    {r['state']} / {r.get('substate', '')}")
        print(f"  Severity: {r.get('severity_rating', 'N/A')}")
        print(f"  Created:  {r['created_at']}")
        if r.get("triaged_at"):
            print(f"  Triaged:  {r['triaged_at']}")
        if r.get("bounty_awarded_at"):
            print(f"  Bounty:   {r['bounty_awarded_at']}")
        if r.get("closed_at"):
            print(f"  Closed:   {r['closed_at']}")
        print(f"  URL:      {r['url']}")
        if r.get("vulnerability_information"):
            print(f"\n  Description:\n{textwrap.indent(r['vulnerability_information'][:500], '    ')}")
        print()

    elif args.subcmd == "balance":
        bal = hackerone.get_balance()
        print(f"\n  HackerOne Balance: ${bal['balance']} {bal['currency']}\n")

    elif args.subcmd == "earnings":
        summary = hackerone.get_earnings_summary()
        print(f"\n═══ HackerOne Earnings ═══\n")
        print(f"  Total earned:    ${summary['total_earned']:.2f}")
        print(f"  Total bounties:  {summary['total_bounties']}")
        print(f"  Average bounty:  ${summary['average_bounty']:.2f}")
        if summary["by_month"]:
            print(f"\n  Monthly Breakdown:")
            for month, amount in list(summary["by_month"].items())[:12]:
                bar = "█" * max(1, int(amount / 100))
                print(f"    {month}  ${amount:>8.2f}  {bar}")
        print()

    elif args.subcmd == "watch":
        handle = _resolve_h1_handle(args)
        result = hackerone.watch_program(handle)
        print(f"\n  ✓ Watching '{result['handle']}' ({result['name']})")
        print(f"    Scope snapshot: {result['scopes_snapshotted']} assets")
        if result['project_id']:
            print(f"    Linked to project [{result['project_id']}]")
        print(f"\n  Check for changes: bb h1 check {result['handle']}\n")

    elif args.subcmd == "unwatch":
        handle = _resolve_h1_handle(args)
        hackerone.unwatch_program(handle)
        print(f"\n  ✓ Stopped watching '{handle}'.\n")

    elif args.subcmd == "watchlist":
        watched = hackerone.list_watched()
        if not watched:
            print("\n  No programs being watched. Run 'bb h1 watch <handle>' to start.\n")
            return
        print(f"\n  Watched Programs ({len(watched)}):\n")
        rows = []
        for w in watched:
            linked = f"[{w['project_id']}]" if w['project_id'] else "-"
            checked = w['last_checked_at'][:16] if w['last_checked_at'] else "never"
            changed = w['last_changed_at'][:16] if w['last_changed_at'] else "never"
            rows.append({"handle": w['handle'], "name": w['name'] or '', "scope": str(w['scope_count']),
                        "project": linked, "last_checked": checked, "last_change": changed})
        print(format_table(rows, ["handle", "name", "scope", "project", "last_checked", "last_change"]))

    elif args.subcmd == "check":
        if args.new_programs:
            new_progs = hackerone.check_new_programs()
            if not new_progs:
                print("\n  No new programs found.\n")
                return
            print(f"\n  New HackerOne Programs ({len(new_progs)}):\n")
            rows = []
            for p in new_progs[:25]:
                bounty = "💰" if p.get("offers_bounties") else "  "
                rows.append({"handle": p['handle'], "name": p['name'][:40], "bounty": bounty})
            print(format_table(rows, ["handle", "name", "bounty"]))
            print(f"\n  Watch a program: bb h1 watch <handle>\n")
            return

        if args.handle:
            results = [hackerone.check_program(args.handle, auto_import=args.auto_import)]
        else:
            results = hackerone.check_all_watched(auto_import=args.auto_import)

        if not results:
            print("\n  No programs being watched. Run 'bb h1 watch <handle>' to start.\n")
            return

        total_changes = 0
        for r in results:
            status = "🔔 CHANGES" if r['has_changes'] else "✓ no changes"
            print(f"\n  [{r['handle']}] {r['name']} — {status}")
            if r['new']:
                print(f"    + {len(r['new'])} new assets:")
                for s in r['new']:
                    bounty = " 💰" if s.get('eligible_for_bounty') else ""
                    print(f"      {s['asset_type']:12s} {s['asset_identifier']}{bounty}")
            if r['removed']:
                print(f"    - {len(r['removed'])} removed assets:")
                for s in r['removed']:
                    print(f"      {s['asset_type']:12s} {s['asset_identifier']}")
            if r['changed']:
                print(f"    ~ {len(r['changed'])} changed assets:")
                for s in r['changed']:
                    changes = ', '.join(f"{k}: {v['old']}→{v['new']}" for k, v in s['changes'].items())
                    print(f"      {s['asset_identifier']}: {changes}")
            if r.get('auto_imported'):
                print(f"    ↳ Auto-imported {r['auto_imported']} new targets into project [{r['project_id']}]")
            total_changes += len(r.get('new', [])) + len(r.get('removed', [])) + len(r.get('changed', []))

        print(f"\n  Summary: {len(results)} programs checked, {total_changes} total changes.\n")

    elif args.subcmd == "notify":
        if args.channel in ("discord", "discord-scope", "discord-programs"):
            event = None
            if args.channel == "discord-scope":
                event = "scope"
            elif args.channel == "discord-programs":
                event = "programs"
            if args.value:
                err = notifier.configure_discord(args.value, event=event)
                if err:
                    print(f"\n  ✗ Invalid webhook URL: {err}\n")
                    return
                ok = notifier.test_discord(event=event)
                label = f" ({event})" if event else ""
                if ok:
                    print(f"\n  ✓ Discord{label} webhook saved and verified! Test message sent.\n")
                else:
                    print(f"\n  ⚠ Webhook saved but test message failed. Check the URL and channel permissions.\n")
            else:
                status = notifier.get_status()
                key = "discord" if not event else f"discord_{event}"
                d = status[key]
                label = f" ({event})" if event else ""
                if d['configured']:
                    extra = " (using default)" if d.get('uses_default') else ""
                    print(f"\n  Discord{label}: ✓ configured (via {d['source']}){extra}\n")
                else:
                    print(f"\n  Discord{label}: not configured.")
                    env_var = f"BBRADAR_DISCORD_{event.upper()}_WEBHOOK" if event else "BBRADAR_DISCORD_WEBHOOK"
                    print(f"  Set via env var: export {env_var}=<url>")
                    print(f"  Or via command:  bb h1 notify {args.channel} <webhook_url>\n")

        elif args.channel == "desktop":
            if args.value in ("on", "enable", "true", "1", None):
                notifier.configure_desktop(True)
                ok = notifier.test_desktop()
                if ok:
                    print("\n  ✓ Desktop notifications enabled and tested.\n")
                else:
                    print("\n  ⚠ Enabled but notify-send not found. Install libnotify.\n")
            elif args.value in ("off", "disable", "false", "0"):
                notifier.configure_desktop(False)
                print("\n  ✓ Desktop notifications disabled.\n")
            else:
                print("\n  Usage: bb h1 notify desktop [on|off]\n")

        elif args.channel == "test":
            print("\n  Testing notification channels...\n")
            status = notifier.get_status()
            any_configured = False
            for key, label in [("discord", "Discord (default)"),
                               ("discord_scope", "Discord (scope)"),
                               ("discord_programs", "Discord (programs)")]:
                d = status[key]
                if d['configured'] and not d.get('uses_default'):
                    any_configured = True
                    event = None if key == "discord" else key.split("_", 1)[1]
                    ok = notifier.test_discord(event=event)
                    url_display = notifier.mask_webhook_url(notifier._get_discord_webhook(event))
                    print(f"    {label}: {'✓ sent' if ok else '✗ failed'} ({url_display})")
                elif d['configured']:
                    print(f"    {label}: using default")
                else:
                    print(f"    {label}: not configured")
            if status['desktop']['enabled']:
                any_configured = True
                ok = notifier.test_desktop()
                print(f"    Desktop: {'✓ sent' if ok else '✗ failed (is notify-send installed?)'}")
            else:
                print("    Desktop: disabled")
            if not any_configured:
                print("\n  No channels configured. Set one up with:")
                print("    bb h1 notify discord <webhook_url>")
            print()

        else:  # status
            status = notifier.get_status()
            print("\n  Notification Channels:\n")
            d = status['discord']
            print(f"    Discord (default):  {'✓ configured' if d['configured'] else '✗ not configured'}" +
                  (f" (via {d['source']})" if d['configured'] else ""))
            ds = status['discord_scope']
            if ds['configured'] and not ds.get('uses_default'):
                print(f"    Discord (scope):    ✓ configured (via {ds['source']})")
            elif ds['configured']:
                print(f"    Discord (scope):    → using default")
            else:
                print(f"    Discord (scope):    ✗ not configured")
            dp = status['discord_programs']
            if dp['configured'] and not dp.get('uses_default'):
                print(f"    Discord (programs): ✓ configured (via {dp['source']})")
            elif dp['configured']:
                print(f"    Discord (programs): → using default")
            else:
                print(f"    Discord (programs): ✗ not configured")
            print(f"    Desktop:            {'✓ enabled' if status['desktop']['enabled'] else '✗ disabled'}")
            print(f"\n  Configure: bb h1 notify discord <url>           # default for all")
            print(f"             bb h1 notify discord-scope <url>     # scope changes")
            print(f"             bb h1 notify discord-programs <url>  # new programs")
            print(f"             bb h1 notify desktop on")
            print(f"  Test:      bb h1 notify test\n")

    elif args.subcmd == "monitor":
        quiet = args.quiet

        # Check watched programs
        results = hackerone.check_all_watched(auto_import=args.auto_import)
        changed = [r for r in results if r.get('has_changes')]

        # Check for newly launched programs
        new_progs = hackerone.check_new_programs()

        # Print results (unless --quiet and nothing changed)
        if not quiet or changed or new_progs:
            if changed:
                for r in changed:
                    print(f"  🔔 [{r['handle']}] {r['name']}")
                    if r['new']:
                        for s in r['new']:
                            bounty = " 💰" if s.get('eligible_for_bounty') else ""
                            print(f"    + {s['asset_identifier']} ({s['asset_type']}){bounty}")
                    if r['removed']:
                        for s in r['removed']:
                            print(f"    - {s['asset_identifier']} ({s['asset_type']})")
                    if r['changed']:
                        for s in r['changed']:
                            changes = ', '.join(f"{k}: {v['old']}→{v['new']}" for k, v in s['changes'].items())
                            print(f"    ~ {s['asset_identifier']}: {changes}")
                    if r.get('auto_imported'):
                        print(f"    ↳ Auto-imported {r['auto_imported']} targets")
            elif not quiet:
                print(f"  ✓ {len(results)} programs checked — no scope changes.")

            if new_progs:
                print(f"\n  🆕 {len(new_progs)} new programs:")
                for p in new_progs[:10]:
                    bounty = " 💰" if p.get('offers_bounties') else ""
                    print(f"    {p['handle']}: {p['name'][:40]}{bounty}")

        # Send notifications
        notif_result = notifier.notify_scope_changes(results)
        if new_progs:
            notifier.notify_new_programs(new_progs)

        # Check for new hacktivity disclosures on watched programs
        new_disclosures = hackerone.check_new_hacktivity()
        if new_disclosures:
            if not quiet:
                for d in new_disclosures:
                    print(f"\n  📄 [{d['handle']}] {len(d['new_reports'])} new disclosed reports:")
                    for r in d['new_reports'][:5]:
                        sev = r.get('severity_rating', '-')
                        bounty = f" ${r['total_awarded_amount']}" if r.get('total_awarded_amount') else ""
                        print(f"    {sev:8s} {r['title'][:60]}{bounty}")
            notifier.notify_new_hacktivity(new_disclosures)

        if not quiet:
            sent_to = []
            if notif_result.get('discord'):
                sent_to.append('Discord')
            if notif_result.get('desktop'):
                sent_to.append('Desktop')
            if sent_to:
                print(f"\n  📨 Notifications sent: {', '.join(sent_to)}")
            elif changed:
                print(f"\n  ⚠ Changes detected but no notification channels configured.")
                print(f"    Run: bb h1 notify discord <webhook_url>")

    elif args.subcmd == "intel":
        handle = _resolve_h1_handle(args)
        if not getattr(args, "json", False):
            print(f"\n  Fetching intel for '{handle}'...")
        intel = hackerone.get_program_intel(handle, refresh=args.refresh)
        if _json_out(args, intel):
            return
        stats = intel["stats"]

        bounty_str = "💰 Yes" if intel["offers_bounties"] else "No"
        print(f"\n═══ Program Intel: {intel['handle']} ═══\n")
        print(f"  Program:   {intel['name']}")
        print(f"  Bounties:  {bounty_str}")
        print(f"  Disclosed: {stats['total_disclosed']} reports")

        # Severity breakdown
        if stats["by_severity"]:
            print(f"\n  Severity Breakdown:")
            for sev in ("critical", "high", "medium", "low", "none"):
                count = stats["by_severity"].get(sev, 0)
                if count:
                    bar = "█" * min(count, 40)
                    print(f"    {sev:10s} {count:3d}  {bar}")

        # Bounty stats
        if stats["bounty_count"]:
            print(f"\n  Bounty Stats ({stats['bounty_count']} paid):")
            print(f"    Min:   ${stats['bounty_min']:,.0f}")
            print(f"    Max:   ${stats['bounty_max']:,.0f}")
            print(f"    Avg:   ${stats['bounty_avg']:,.0f}")
            print(f"    Total: ${stats['bounty_total']:,.0f}")

        # Top CWEs
        if stats["top_cwes"]:
            print(f"\n  Top Vulnerability Types:")
            for cwe, count in stats["top_cwes"]:
                print(f"    {count:3d}  {cwe}")

        # Top reporters
        if stats["top_reporters"]:
            print(f"\n  Top Reporters:")
            for reporter, count in stats["top_reporters"]:
                print(f"    {count:3d}  {reporter}")

        # Recent disclosures
        recent = intel["hacktivity"][:10]
        if recent:
            print(f"\n  Recent Disclosed Reports:")
            rows = []
            for r in recent:
                bounty = f"${r['total_awarded_amount']:,.0f}" if r.get('total_awarded_amount') else "-"
                date = (r.get("disclosed_at") or "")[:10]
                rows.append({
                    "severity": r.get("severity_rating", "-"),
                    "title": r["title"][:50],
                    "bounty": bounty,
                    "date": date,
                })
            print(format_table(rows, ["severity", "title", "bounty", "date"]))

        # Weaknesses
        if intel["weaknesses"]:
            print(f"\n  Accepted Weakness Types ({len(intel['weaknesses'])}):")
            for w in intel["weaknesses"][:15]:
                cwe = f" ({w['external_id']})" if w.get("external_id") else ""
                print(f"    • {w['name']}{cwe}")
            if len(intel["weaknesses"]) > 15:
                print(f"    ...and {len(intel['weaknesses']) - 15} more")

        print(f"\n  Use 'bb h1 weaknesses {handle}' for full weakness list.\n")

    elif args.subcmd == "weaknesses":
        handle = _resolve_h1_handle(args)
        print(f"\n  Fetching weaknesses for '{handle}'...")

        if args.refresh or not hackerone._intel_cache_fresh(handle, "h1_weakness_cache"):
            weaknesses = hackerone.get_weaknesses(handle)
            hackerone.cache_weaknesses(handle, weaknesses)
        else:
            weaknesses = hackerone.get_cached_weaknesses(handle)

        if _json_out(args, weaknesses):
            return

        if not weaknesses:
            print(f"\n  No weakness types found for '{handle}'.\n")
            return

        print(f"\n═══ Accepted Weaknesses: {handle} ({len(weaknesses)}) ═══\n")
        rows = []
        for w in weaknesses:
            rows.append({
                "cwe": w.get("external_id", ""),
                "name": w["name"][:60],
            })
        print(format_table(rows, ["cwe", "name"]))
        print()

    else:
        print("Usage: bb h1 {auth|status|programs|search|import|scope-sync|reports|report|balance|earnings|watch|unwatch|watchlist|check|notify|monitor|intel|weaknesses}")


def cmd_dashboard(args):
    """Show combined BBRadar + HackerOne dashboard."""
    data = hackerone.get_dashboard_data()
    local = data["local"]
    h1 = data["hackerone"]

    print("\n╔═══════════════════════════════════════════════════╗")
    print("║              BBRadar Dashboard                    ║")
    print("╚═══════════════════════════════════════════════════╝\n")

    # Local stats
    print("  📁 Projects")
    print(f"    Active:  {local['active_projects']} / {local['total_projects']} total")
    if local.get("projects"):
        for p in local["projects"][:5]:
            print(f"      [{p['id']}] {p['name']}")

    print(f"\n  🔍 Findings: {local['total_vulns']} total")
    for sev in ("critical", "high", "medium", "low"):
        count = local["vulns_by_severity"].get(sev, 0)
        if count:
            print(f"    {severity_color(sev)}: {count}")

    status_parts = []
    for st in ("new", "confirmed", "reported", "accepted", "resolved"):
        count = local["vulns_by_status"].get(st, 0)
        if count:
            status_parts.append(f"{st}: {count}")
    if status_parts:
        print(f"    Pipeline: {' → '.join(status_parts)}")

    if local.get("local_bounty_total"):
        print(f"\n  💰 Local bounty tracking: ${local['local_bounty_total']:.2f}")

    # HackerOne stats
    print(f"\n  {'─' * 45}")
    if h1.get("connected"):
        print(f"\n  🌐 HackerOne ({h1['username']})")
        print(f"    Balance:  ${h1['balance']} {h1['currency']}")
        print(f"    Reports:  {h1['total_reports']} submitted")
        if h1.get("report_states"):
            parts = [f"{st}: {cnt}" for st, cnt in h1["report_states"].items()]
            print(f"    States:   {', '.join(parts)}")

        # Hit rate
        total = h1["total_reports"]
        resolved = h1["report_states"].get("resolved", 0)
        triaged = h1["report_states"].get("triaged", 0)
        if total > 0:
            accepted = resolved + triaged
            rate = (accepted / total) * 100
            print(f"    Hit rate: {rate:.0f}% ({accepted}/{total} accepted)")
    else:
        print(f"\n  🌐 HackerOne: not connected")
        print(f"    Run 'bb h1 auth' to connect your account.")

    print()


# ═══════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════

COMMAND_MAP = {
    "init": cmd_init,
    "status": cmd_status,
    "use": cmd_use,
    "completion": cmd_completion,
    "project": cmd_project,
    "target": cmd_target,
    "recon": cmd_recon,
    "vuln": cmd_vuln,
    "note": cmd_note,
    "report": cmd_report,
    "workflow": cmd_workflow,
    "wizard": cmd_wizard,
    "templates": cmd_templates,
    "ingest": cmd_ingest,
    "scope": cmd_scope,
    "kb": cmd_kb,
    "audit": cmd_audit,
    "config": cmd_config,
    "db": cmd_db,
    "evidence": cmd_evidence,
    "h1": cmd_h1,
    "dashboard": cmd_dashboard,
}


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Handle --no-color / NO_COLOR env var
    if getattr(args, "no_color", False) or os.environ.get("NO_COLOR") is not None:
        set_no_color(True)

    if not args.command:
        # Show status by default instead of --help wall of text
        try:
            cmd_status(args)
        except Exception:
            # Not initialized yet — show quick start guidance
            print("\n  BBRadar is not initialized yet.\n")
            print("  Quick start:")
            print("    bb init                      Initialize BBRadar")
            print("    bb wizard project            Create your first project")
            print("    bb use <id>                  Set active project")
            print("    bb wizard vuln               Log a finding")
            print("\n  HackerOne:")
            print("    bb h1 auth                   Connect your account")
            print("    bb h1 import <program>       Import a program")
            print("    bb dashboard                 View dashboard")
            print("\n  Run 'bb --help' for all commands.\n")
        sys.exit(0)

    handler = COMMAND_MAP.get(args.command)
    if handler:
        try:
            handler(args)
        except KeyboardInterrupt:
            print("\nAborted.", file=sys.stderr)
            sys.exit(130)
        except Exception as e:
            msg = str(e)
            # Translate cryptic SQLite errors
            if "FOREIGN KEY constraint failed" in msg:
                msg = "Referenced project/target/vuln does not exist. Check the ID."
            elif "UNIQUE constraint failed: projects.name" in msg:
                msg = "A project with that name already exists."
            elif "UNIQUE constraint failed" in msg:
                msg = f"Duplicate entry: {msg}"
            print(f"\n❌ Error: {msg}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"\n❌ Unknown command '{args.command}'.", file=sys.stderr)
        # Suggest closest match
        import difflib
        close = difflib.get_close_matches(args.command, COMMAND_MAP.keys(), n=3, cutoff=0.5)
        if close:
            print(f"   Did you mean: {', '.join(close)}?", file=sys.stderr)
        print(f"\n   Run 'bb --help' for available commands.\n", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
