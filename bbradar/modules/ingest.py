"""
Ingest pipeline — parse tool output, deduplicate, enrich with KB, create draft vulns.

Usage flow:
    1. Detect tool (auto or explicit)
    2. Parse output → list of normalized finding dicts
    3. Deduplicate against existing vulns in the project
    4. Optionally enrich from KB (CWE, CAPEC, VRT, templates)
    5. Create draft vulns (status='new') in the database
    6. Return triage summary
"""

import os
import sys
from pathlib import Path

from ..core.database import get_connection
from ..core.utils import timestamp_now
from ..modules import vulns
from .parsers import detect_tool, get_parser, list_parsers


def ingest_file(filepath: str, project_id: int, tool_hint: str = None,
                dry_run: bool = False, enrich: bool = True,
                min_severity: str = "informational",
                scope_check: bool = False,
                db_path=None) -> dict:
    """
    Ingest a single tool output file into a project.

    Returns a summary dict:
        {tool, file, total_parsed, new, duplicates, skipped, created_ids, findings}
    """
    filepath = os.path.abspath(filepath)
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    with open(filepath, "r", errors="replace") as f:
        data = f.read()

    return ingest_data(data, project_id, tool_hint=tool_hint,
                       filename=filepath, dry_run=dry_run, enrich=enrich,
                       min_severity=min_severity, scope_check=scope_check,
                       db_path=db_path)


def ingest_stdin(project_id: int, tool_hint: str = None,
                 dry_run: bool = False, enrich: bool = True,
                 min_severity: str = "informational",
                 scope_check: bool = False,
                 db_path=None) -> dict:
    """Ingest tool output from stdin."""
    data = sys.stdin.read()
    if not data.strip():
        return _empty_result("stdin", "stdin")

    return ingest_data(data, project_id, tool_hint=tool_hint,
                       filename="stdin", dry_run=dry_run, enrich=enrich,
                       min_severity=min_severity, scope_check=scope_check,
                       db_path=db_path)


def ingest_directory(dirpath: str, project_id: int,
                     dry_run: bool = False, enrich: bool = True,
                     min_severity: str = "informational",
                     scope_check: bool = False,
                     db_path=None) -> list[dict]:
    """Ingest all recognizable tool output files from a directory."""
    dirpath = os.path.abspath(dirpath)
    if not os.path.isdir(dirpath):
        raise NotADirectoryError(f"Not a directory: {dirpath}")

    results = []
    eligible = []
    for root, _dirs, files in os.walk(dirpath):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            # Skip very large files (> 50MB) and non-text
            try:
                size = os.path.getsize(fpath)
                if size > 50 * 1024 * 1024:
                    continue
                if size == 0:
                    continue
            except OSError:
                continue

            # Try to detect tool
            tool = detect_tool(filepath=fpath)
            if not tool:
                continue
            eligible.append((fpath, tool))

    total = len(eligible)
    for idx, (fpath, tool) in enumerate(eligible, 1):
        print(f"  [{idx}/{total}] Ingesting {os.path.basename(fpath)} ({tool})...",
              file=__import__('sys').stderr, flush=True)
        try:
            result = ingest_file(fpath, project_id, tool_hint=tool,
                                 dry_run=dry_run, enrich=enrich,
                                 min_severity=min_severity,
                                 scope_check=scope_check, db_path=db_path)
            results.append(result)
        except Exception as e:
            results.append({
                "tool": tool or "unknown",
                "file": fpath,
                "total_parsed": 0,
                "new": 0,
                "duplicates": 0,
                "skipped": 0,
                "created_ids": [],
                "findings": [],
                "error": str(e),
            })

    return results


def ingest_data(data: str, project_id: int, tool_hint: str = None,
                filename: str = "", dry_run: bool = False,
                enrich: bool = True, min_severity: str = "informational",
                scope_check: bool = False,
                db_path=None) -> dict:
    """
    Core ingest: parse raw data, dedup, enrich, create drafts.
    """
    # Step 1: Detect tool
    tool = detect_tool(filepath=filename if filename != "stdin" else None,
                       data=data, hint=tool_hint)
    if not tool:
        return _empty_result("unknown", filename, error="Could not detect tool. Use --tool to specify.")

    # Step 2: Parse
    parser = get_parser(tool)
    if not parser:
        return _empty_result(tool, filename, error=f"No parser registered for '{tool}'.")

    try:
        findings = parser.parse(data, filename)
    except Exception as e:
        return _empty_result(tool, filename, error=f"Parse error: {e}")

    if not findings:
        return _empty_result(tool, filename)

    total_before_severity = len(findings)

    # Step 3: Filter by minimum severity
    sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
    min_sev_val = sev_order.get(min_severity, 0)
    if min_sev_val > 1:
        findings = [f for f in findings if sev_order.get(f.get("severity", "informational"), 0) >= min_sev_val]

    severity_filtered = total_before_severity - len(findings)
    total_parsed = len(findings)

    # Step 4: Deduplicate against existing project vulns + within batch
    findings, dup_count = _deduplicate(findings, project_id, db_path)

    # Step 4b: Scope filtering — drop findings for out-of-scope hosts
    out_of_scope_count = 0
    if scope_check and findings:
        from ..modules import scope as scope_mod
        # Check if project has any scope rules
        rules = scope_mod.list_rules(project_id, db_path=db_path)
        if rules:
            scoped = []
            for f in findings:
                host = f.get("host") or f.get("url") or f.get("target") or ""
                if not host:
                    scoped.append(f)  # can't check, keep it
                    continue
                result = scope_mod.check_scope(project_id, host, db_path=db_path)
                if result["in_scope"] is False:
                    out_of_scope_count += 1
                else:
                    scoped.append(f)
            findings = scoped

    # Step 5: Enrich from KB
    if enrich and findings:
        findings = _enrich_findings(findings, db_path)

    # Step 6: Create draft vulns (unless dry_run)
    created_ids = []
    create_errors = []
    if not dry_run:
        for f in findings:
            try:
                vid = _create_draft_vuln(f, project_id, db_path)
                created_ids.append(vid)
            except Exception as e:
                create_errors.append(f"{f.get('title', 'Untitled')[:50]}: {e}")

    skipped = total_parsed - len(findings) - dup_count - out_of_scope_count

    result = {
        "tool": tool,
        "file": filename,
        "total_parsed": total_before_severity,
        "severity_filtered": severity_filtered,
        "new": len(findings),
        "duplicates": dup_count,
        "out_of_scope": out_of_scope_count,
        "skipped": max(0, skipped),
        "created_ids": created_ids,
        "create_errors": create_errors,
        "findings": findings if dry_run else [],
    }

    # Notify on new findings (pass findings for severity breakdown even on non-dry-run)
    if not dry_run and created_ids:
        try:
            from .notifier import notify_ingest_complete
            notif_result = dict(result)
            notif_result["findings"] = findings  # always include for severity count
            notify_ingest_complete(notif_result, project_id, db_path=db_path)
        except Exception:
            pass  # never let notification failure break ingest

    return result


def get_ingest_summary(project_id: int, db_path=None) -> dict:
    """Get a summary of ingested findings for a project."""
    all_vulns = vulns.list_vulns(project_id=project_id, limit=10000, db_path=db_path)

    by_tool = {}
    by_severity = {}
    by_type = {}

    for v in all_vulns:
        # Check for tool tag in description or evidence
        tool = "manual"
        desc = v.get("description") or ""
        if "[ingested:" in desc:
            start = desc.index("[ingested:") + 10
            end = desc.index("]", start) if "]" in desc[start:] else start + 20
            tool = desc[start:end].strip()

        by_tool[tool] = by_tool.get(tool, 0) + 1
        sev = v.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        vt = v.get("vuln_type") or "other"
        by_type[vt] = by_type.get(vt, 0) + 1

    return {
        "total": len(all_vulns),
        "by_tool": by_tool,
        "by_severity": by_severity,
        "by_type": by_type,
    }


# ═══════════════════════════════════════════════════════════════════
# Internal helpers
# ═══════════════════════════════════════════════════════════════════

def _deduplicate(findings: list[dict], project_id: int, db_path=None) -> tuple[list[dict], int]:
    """
    Deduplicate findings against existing vulns and within the batch.
    Returns (unique_findings, duplicate_count).
    """
    existing = vulns.list_vulns(project_id=project_id, limit=10000, db_path=db_path)

    existing_fingerprints = set()
    for v in existing:
        # Build rough fingerprints from existing vulns
        parts = [
            (v.get("description") or "")[:60].lower(),
            (v.get("title") or "").lower(),
            v.get("vuln_type") or "",
        ]
        existing_fingerprints.add("|".join(parts))

        # Also match by title similarity
        existing_fingerprints.add((v.get("title") or "").lower().strip())

    seen_fp = set()
    unique = []
    dup_count = 0

    for f in findings:
        fp = f.get("fingerprint", "")

        # Check within-batch dedup
        if fp in seen_fp:
            dup_count += 1
            continue

        # Check against existing vulns — match by fingerprint-like fields
        title_lower = f.get("title", "").lower().strip()
        desc_key = f"{f.get('description', '')[:60].lower()}|{title_lower}|{f.get('vuln_type', '')}"

        if title_lower in existing_fingerprints or desc_key in existing_fingerprints:
            dup_count += 1
            seen_fp.add(fp)
            continue

        # Check CVE dedup
        cve = f.get("cve_id", "")
        if cve:
            for v in existing:
                existing_desc = (v.get("description") or "").lower()
                if cve.lower() in existing_desc or cve.lower() in (v.get("title") or "").lower():
                    dup_count += 1
                    seen_fp.add(fp)
                    break
            else:
                seen_fp.add(fp)
                unique.append(f)
                continue
            continue

        seen_fp.add(fp)
        unique.append(f)

    return unique, dup_count


def _enrich_findings(findings: list[dict], db_path=None) -> list[dict]:
    """Enrich findings with KB data where available."""
    try:
        from ..modules import knowledgebase
    except ImportError:
        return findings

    for f in findings:
        cwe_id = f.get("cwe_id", "")
        if cwe_id:
            # Strip prefix for lookup
            cwe_num = cwe_id.replace("CWE-", "").strip()
            cwe = knowledgebase.lookup_cwe(cwe_num, db_path=db_path)
            if cwe:
                if not f.get("description"):
                    f["description"] = cwe.get("description", "")
                # Add CWE name to title if not already there
                cwe_name = cwe.get("name", "")
                if cwe_name and cwe_name.lower() not in f.get("title", "").lower():
                    f["description"] = f"[{cwe_id}: {cwe_name}] {f['description']}"

    return findings


def _create_draft_vuln(finding: dict, project_id: int, db_path=None) -> int:
    """Create a draft vulnerability from a parsed finding."""
    # Normalize vuln_type to valid types
    vuln_type = finding.get("vuln_type", "other")
    if vuln_type not in vulns.VALID_VULN_TYPES:
        vuln_type = _map_vuln_type(vuln_type)

    # Build description with provenance
    desc_parts = []
    if finding.get("description"):
        desc_parts.append(finding["description"])
    desc_parts.append(f"\n[ingested:{finding.get('tool', 'unknown')}]")

    description = "\n".join(desc_parts)

    # Truncate evidence for DB storage
    evidence = finding.get("evidence", "")
    if len(evidence) > 5000:
        evidence = evidence[:5000] + "\n...(truncated)"

    evidence_list = [evidence] if evidence else None

    vid = vulns.create_vuln(
        project_id=project_id,
        title=finding.get("title", "Untitled finding")[:200],
        severity=finding.get("severity", "informational"),
        vuln_type=vuln_type,
        description=description,
        request=finding.get("request", "") or None,
        response=finding.get("response", "") or None,
        evidence=evidence_list,
        cvss_score=finding.get("cvss_score"),
        db_path=db_path,
    )
    return vid


def _map_vuln_type(raw_type: str) -> str:
    """Map parser vuln_type strings to valid vulns module types."""
    mapping = {
        "ssl_tls": "other",
        "security_headers": "other",
        "misconfiguration": "other",
        "session_management": "other",
        "known_cve": "other",
        "injection": "sqli",
        "file_upload": "other",
        "clickjacking": "other",
        "code_quality": "other",
        "cryptographic_issue": "other",
        "privilege_escalation": "broken_access_control",
        "info_disclosure": "info_disclosure",
    }
    return mapping.get(raw_type, "other")


def _empty_result(tool: str, filename: str, error: str = "") -> dict:
    return {
        "tool": tool,
        "file": filename,
        "total_parsed": 0,
        "new": 0,
        "duplicates": 0,
        "skipped": 0,
        "created_ids": [],
        "findings": [],
        "error": error,
    }
