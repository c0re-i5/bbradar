"""
Report generator module.

Produces professional Markdown and HTML reports for bug bounty submissions
and assessment documentation. Supports single-vuln, full-project, and
executive summary report types.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from ..core.database import get_connection
from ..core.audit import log_action
from ..core.config import load_config
from ..core.utils import slugify, ensure_file_dir
from .projects import get_project, get_project_stats
from .vulns import get_vuln, list_vulns, get_vuln_stats
from .targets import list_targets
from .notes import list_notes


def generate_single_vuln_report(vuln_id: int, format: str = "markdown",
                                output_path: str = None, db_path=None) -> str:
    """
    Generate a report for a single vulnerability — suitable for
    bug bounty platform submission (HackerOne, Bugcrowd, etc.).
    Returns the output file path.
    """
    vuln = get_vuln(vuln_id, db_path)
    if not vuln:
        raise ValueError(f"Vulnerability #{vuln_id} not found")

    project = get_project(vuln["project_id"], db_path=db_path)
    cfg = load_config()

    # Build markdown content
    md = _render_single_vuln_md(vuln, project, cfg)

    # Determine output path
    if not output_path:
        slug = slugify(vuln["title"])
        output_path = str(
            Path(cfg["reports_dir"]) / f"vuln_{vuln_id}_{slug}.md"
        )

    ensure_file_dir(Path(output_path))

    if format == "html":
        html = _md_to_html(md, title=vuln["title"])
        output_path = output_path.replace(".md", ".html")
        Path(output_path).write_text(html)
    else:
        Path(output_path).write_text(md)

    # Record in DB
    with get_connection(db_path) as conn:
        conn.execute(
            """INSERT INTO reports (project_id, vuln_id, report_type, format, file_path)
               VALUES (?, ?, 'single', ?, ?)""",
            (vuln["project_id"], vuln_id, format, output_path),
        )
    log_action("generated_report", "report", None,
               {"vuln_id": vuln_id, "format": format, "file": output_path}, db_path)
    return output_path


def generate_full_report(project_id: int, format: str = "markdown",
                         output_path: str = None, db_path=None) -> str:
    """
    Generate a comprehensive report for an entire project —
    all findings, recon summary, notes.
    Returns the output file path.
    """
    project = get_project(project_id, db_path=db_path)
    if not project:
        raise ValueError(f"Project #{project_id} not found")

    cfg = load_config()
    stats = get_project_stats(project_id, db_path)
    vulns = list_vulns(project_id=project_id, limit=1000, db_path=db_path)
    targets = list_targets(project_id, db_path=db_path)
    notes = list_notes(project_id=project_id, limit=1000, db_path=db_path)

    md = _render_full_report_md(project, stats, vulns, targets, notes, cfg)

    if not output_path:
        slug = slugify(project["name"])
        ts = datetime.now(timezone.utc).strftime("%Y%m%d")
        output_path = str(
            Path(cfg["reports_dir"]) / f"report_{slug}_{ts}.md"
        )

    ensure_file_dir(Path(output_path))

    if format == "html":
        html = _md_to_html(md, title=f"Security Assessment — {project['name']}")
        output_path = output_path.replace(".md", ".html")
        Path(output_path).write_text(html)
    else:
        Path(output_path).write_text(md)

    with get_connection(db_path) as conn:
        conn.execute(
            """INSERT INTO reports (project_id, report_type, format, file_path)
               VALUES (?, 'full', ?, ?)""",
            (project_id, format, output_path),
        )
    log_action("generated_report", "report", None,
               {"project_id": project_id, "format": format, "file": output_path}, db_path)
    return output_path


def generate_executive_summary(project_id: int, format: str = "markdown",
                               output_path: str = None, db_path=None) -> str:
    """
    Generate a high-level executive summary — stats, critical/high findings,
    risk overview. Suitable for management or program owners.
    """
    project = get_project(project_id, db_path=db_path)
    if not project:
        raise ValueError(f"Project #{project_id} not found")

    cfg = load_config()
    stats = get_project_stats(project_id, db_path)
    vuln_stats = get_vuln_stats(project_id, db_path)
    critical_vulns = list_vulns(project_id=project_id, severity="critical", db_path=db_path)
    high_vulns = list_vulns(project_id=project_id, severity="high", db_path=db_path)

    md = _render_executive_md(project, stats, vuln_stats, critical_vulns, high_vulns, cfg)

    if not output_path:
        slug = slugify(project["name"])
        ts = datetime.now(timezone.utc).strftime("%Y%m%d")
        output_path = str(
            Path(cfg["reports_dir"]) / f"executive_{slug}_{ts}.md"
        )

    ensure_file_dir(Path(output_path))

    if format == "html":
        html = _md_to_html(md, title=f"Executive Summary — {project['name']}")
        output_path = output_path.replace(".md", ".html")
        Path(output_path).write_text(html)
    else:
        Path(output_path).write_text(md)

    with get_connection(db_path) as conn:
        conn.execute(
            """INSERT INTO reports (project_id, report_type, format, file_path)
               VALUES (?, 'executive', ?, ?)""",
            (project_id, format, output_path),
        )
    log_action("generated_report", "report", None,
               {"project_id": project_id, "type": "executive", "file": output_path}, db_path)
    return output_path


def list_reports(project_id: int = None, db_path=None) -> list[dict]:
    """List generated reports."""
    with get_connection(db_path) as conn:
        if project_id:
            rows = conn.execute(
                "SELECT * FROM reports WHERE project_id = ? ORDER BY created_at DESC",
                (project_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM reports ORDER BY created_at DESC"
            ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Markdown renderers
# ---------------------------------------------------------------------------

def _render_single_vuln_md(vuln: dict, project: dict, cfg: dict) -> str:
    """Render a single vulnerability report in Markdown."""
    severity = vuln["severity"].upper()
    lines = [
        f"# {vuln['title']}",
        "",
        f"**Severity:** {severity}",
    ]
    if vuln.get("cvss_score"):
        lines.append(f"**CVSS Score:** {vuln['cvss_score']} ({vuln.get('cvss_vector', '')})")
    if vuln.get("vuln_type"):
        lines.append(f"**Type:** {vuln['vuln_type'].upper().replace('_', ' ')}")
    # Extract CWE/OWASP from description if embedded by template system
    desc = vuln.get("description", "")
    if "**CWE:**" in desc:
        import re as _re
        _cwe = _re.search(r"\*\*CWE:\*\*\s*(.+)", desc)
        if _cwe:
            lines.append(f"**CWE:** {_cwe.group(1).strip()}")
    if "**OWASP:**" in desc:
        import re as _re
        _owasp = _re.search(r"\*\*OWASP:\*\*\s*(.+)", desc)
        if _owasp:
            lines.append(f"**OWASP:** {_owasp.group(1).strip()}")
    lines.append(f"**Program:** {project['name'] if project else 'N/A'}")
    if project and project.get("platform"):
        lines.append(f"**Platform:** {project['platform']}")
    lines.append(f"**Date:** {vuln['created_at']}")
    lines.append(f"**Status:** {vuln['status']}")
    if cfg.get("report_author"):
        lines.append(f"**Researcher:** {cfg['report_author']}")
    lines.append("")

    if vuln.get("description"):
        lines.extend(["## Description", "", vuln["description"], ""])

    if vuln.get("impact"):
        lines.extend(["## Impact", "", vuln["impact"], ""])

    if vuln.get("reproduction"):
        lines.extend(["## Steps to Reproduce", "", vuln["reproduction"], ""])

    if vuln.get("request"):
        lines.extend([
            "## HTTP Request",
            "",
            "```http",
            vuln["request"],
            "```",
            "",
        ])

    if vuln.get("response"):
        response_text = vuln["response"]
        truncated = len(response_text) > 2000
        lines.extend([
            "## HTTP Response (Excerpt)",
            "",
            "```http",
            response_text[:2000],
            "```",
        ])
        if truncated:
            lines.append(f"\n> **Note:** Response truncated ({len(response_text):,} chars total, showing first 2,000)")
        lines.append("")

    if vuln.get("evidence"):
        evidence = json.loads(vuln["evidence"]) if isinstance(vuln["evidence"], str) else vuln["evidence"]
        if evidence:
            lines.extend(["## Evidence", ""])
            for e in evidence:
                lines.append(f"- `{e}`")
            lines.append("")

    if vuln.get("remediation"):
        lines.extend(["## Remediation", "", vuln["remediation"], ""])

    return "\n".join(lines)


def _render_full_report_md(project: dict, stats: dict, vulns: list[dict],
                           targets: list[dict], notes: list[dict], cfg: dict) -> str:
    """Render a full project assessment report in Markdown."""
    lines = [
        f"# Security Assessment Report — {project['name']}",
        "",
        f"**Date:** {datetime.now(timezone.utc).strftime(cfg.get('date_format', '%Y-%m-%d'))}",
    ]
    if cfg.get("report_author"):
        lines.append(f"**Researcher:** {cfg['report_author']}")
    if cfg.get("report_company"):
        lines.append(f"**Organization:** {cfg['report_company']}")
    if project.get("platform"):
        lines.append(f"**Platform:** {project['platform']}")
    if project.get("program_url"):
        lines.append(f"**Program:** {project['program_url']}")
    lines.extend(["", "---", ""])

    # Table of Contents
    lines.extend([
        "## Table of Contents",
        "",
        "1. [Executive Summary](#executive-summary)",
        "2. [Scope](#scope)",
        "3. [Findings Summary](#findings-summary)",
        "4. [Detailed Findings](#detailed-findings)",
        "5. [Assessment Notes](#assessment-notes)",
        "",
    ])

    # Executive Summary
    lines.extend([
        "## Executive Summary",
        "",
        f"This report documents the findings from the security assessment of **{project['name']}**.",
        "",
        f"- **Total Targets:** {stats['targets']}",
        f"- **Total Findings:** {stats['vulns_total']}",
        f"- **Recon Data Points:** {stats['recon_data_points']}",
    ])
    for sev in ("critical", "high", "medium", "low", "informational"):
        count = stats["vulns_by_severity"].get(sev, 0)
        if count:
            lines.append(f"  - {sev.capitalize()}: {count}")
    lines.extend(["", "---", ""])

    # Scope
    lines.extend(["## Scope", ""])
    if targets:
        lines.append("| # | Type | Asset | In Scope | Tier |")
        lines.append("|---|------|-------|----------|------|")
        for i, t in enumerate(targets, 1):
            scope = "Yes" if t["in_scope"] else "No"
            lines.append(f"| {i} | {t['asset_type']} | `{t['value']}` | {scope} | {t.get('tier', '-')} |")
    else:
        lines.append("*No targets defined.*")
    lines.extend(["", "---", ""])

    # Findings Summary
    lines.extend(["## Findings Summary", ""])
    if vulns:
        lines.append("| # | Title | Severity | Type | Status |")
        lines.append("|---|-------|----------|------|--------|")
        for i, v in enumerate(vulns, 1):
            lines.append(
                f"| {i} | {v['title']} | {v['severity'].upper()} | "
                f"{(v.get('vuln_type') or '-').upper()} | {v['status']} |"
            )
    else:
        lines.append("*No findings recorded.*")
    lines.extend(["", "---", ""])

    # Detailed Findings
    lines.extend(["## Detailed Findings", ""])
    for i, v in enumerate(vulns, 1):
        lines.append(f"### {i}. {v['title']}")
        lines.append("")
        lines.append(f"**Severity:** {v['severity'].upper()}")
        if v.get("cvss_score"):
            lines.append(f"**CVSS:** {v['cvss_score']}")
        if v.get("vuln_type"):
            lines.append(f"**Type:** {v['vuln_type']}")
        lines.append("")
        if v.get("description"):
            lines.extend(["**Description:**", "", v["description"], ""])
        if v.get("impact"):
            lines.extend(["**Impact:**", "", v["impact"], ""])
        if v.get("reproduction"):
            lines.extend(["**Steps to Reproduce:**", "", v["reproduction"], ""])
        if v.get("request"):
            lines.extend(["**HTTP Request:**", "", "```http", v["request"], "```", ""])
        if v.get("remediation"):
            lines.extend(["**Remediation:**", "", v["remediation"], ""])
        lines.extend(["", "---", ""])

    # Notes
    if notes:
        lines.extend(["## Assessment Notes", ""])
        for note in notes[:20]:
            lines.append(f"### {note.get('title') or 'Note'}")
            lines.append(f"*{note['created_at']}*")
            if note.get("tags"):
                lines.append(f"*Tags: {note['tags']}*")
            lines.append("")
            lines.append(note["content"])
            lines.append("")

    return "\n".join(lines)


def _render_executive_md(project: dict, stats: dict, vuln_stats: dict,
                         critical_vulns: list, high_vulns: list, cfg: dict) -> str:
    """Render an executive summary in Markdown."""
    lines = [
        f"# Executive Summary — {project['name']}",
        "",
        f"**Date:** {datetime.now(timezone.utc).strftime(cfg.get('date_format', '%Y-%m-%d'))}",
    ]
    if cfg.get("report_author"):
        lines.append(f"**Researcher:** {cfg['report_author']}")
    lines.extend(["", "---", ""])

    # Risk Overview
    lines.extend([
        "## Risk Overview",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total Findings | {vuln_stats['total']} |",
    ])
    for sev in ("critical", "high", "medium", "low", "informational"):
        count = vuln_stats["by_severity"].get(sev, 0)
        lines.append(f"| {sev.capitalize()} | {count} |")
    if vuln_stats.get("total_bounty"):
        lines.append(f"| Total Bounty | ${vuln_stats['total_bounty']:.2f} |")
    lines.extend(["", ""])

    # Critical/High findings
    if critical_vulns or high_vulns:
        lines.extend(["## Critical & High Severity Findings", ""])
        for v in critical_vulns + high_vulns:
            lines.append(f"- **[{v['severity'].upper()}]** {v['title']} — {v.get('status', 'new')}")
        lines.append("")

    # Status breakdown
    if vuln_stats.get("by_status"):
        lines.extend(["## Finding Status Breakdown", ""])
        for status, count in vuln_stats["by_status"].items():
            lines.append(f"- **{status}:** {count}")
        lines.append("")

    return "\n".join(lines)


def _md_to_html(md_content: str, title: str = "BBRadar Report") -> str:
    """Convert Markdown to a styled HTML document."""
    # Try using the markdown library if available, fall back to basic conversion
    try:
        import markdown
        body = markdown.markdown(md_content, extensions=["tables", "fenced_code"])
    except ImportError:
        # Basic fallback — wrap in pre tags
        import html
        body = f"<pre>{html.escape(md_content)}</pre>"

    # Sanitize rendered HTML to prevent stored XSS
    import re as _re
    # Strip dangerous tags entirely
    for tag in ('script', 'iframe', 'object', 'embed', 'applet', 'form', 'base', 'link'):
        body = _re.sub(rf'<{tag}[^>]*>.*?</{tag}>', '', body, flags=_re.DOTALL | _re.IGNORECASE)
        body = _re.sub(rf'<{tag}[^>]*/>', '', body, flags=_re.IGNORECASE)
    # Strip event handler attributes (on*="...")
    body = _re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', body, flags=_re.IGNORECASE)
    body = _re.sub(r'\s+on\w+\s*=\s*\S+', '', body, flags=_re.IGNORECASE)
    # Strip javascript: and data: URIs in href/src/action attributes
    body = _re.sub(r'(href|src|action)\s*=\s*["\']\s*(javascript|data|vbscript):', r'\1="#blocked:', body, flags=_re.IGNORECASE)

    import html as html_mod
    safe_title = html_mod.escape(title)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{safe_title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 2rem;
            color: #1a1a1a;
            line-height: 1.6;
        }}
        h1 {{ color: #c0392b; border-bottom: 2px solid #c0392b; padding-bottom: 0.5rem; }}
        h2 {{ color: #2c3e50; margin-top: 2rem; }}
        h3 {{ color: #34495e; }}
        table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
        th, td {{ border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; }}
        th {{ background-color: #2c3e50; color: white; }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        code {{ background-color: #f4f4f4; padding: 0.2rem 0.4rem; border-radius: 3px; font-size: 0.9em; }}
        pre {{ background-color: #2c3e50; color: #ecf0f1; padding: 1rem; border-radius: 5px; overflow-x: auto; }}
        pre code {{ background: none; color: inherit; }}
        hr {{ border: none; border-top: 1px solid #ddd; margin: 2rem 0; }}
        @media print {{
            body {{ font-size: 11pt; }}
            pre {{ white-space: pre-wrap; }}
        }}
    </style>
</head>
<body>
{body}
</body>
</html>"""
