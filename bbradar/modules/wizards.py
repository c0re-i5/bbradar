"""
Interactive wizards for BBRadar.

Guided prompts that walk through creating projects, targets, vulns, etc.
instead of requiring long CLI commands with many flags.
"""

import sys
from .vuln_templates import (
    list_template_keys, get_template, search_templates,
    fill_template, get_templates_by_category, VULN_TEMPLATES,
)
from .projects import create_project, list_projects, get_project
from .targets import add_target, list_targets, get_target, VALID_ASSET_TYPES, VALID_TIERS
from .vulns import create_vuln, update_vuln, add_evidence, find_duplicates, VALID_VULN_TYPES
from .notes import create_note
from .scope import check_scope, list_rules
from ..core.utils import severity_color


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _prompt(label: str, default: str = "", required: bool = False) -> str:
    """Prompt user for input with optional default."""
    suffix = f" [{default}]" if default else ""
    while True:
        val = input(f"  {label}{suffix}: ").strip()
        if not val and default:
            return default
        if not val and required:
            print("    (required — please enter a value)")
            continue
        return val


def _prompt_choice(label: str, choices: list[str], default: str = "") -> str:
    """Prompt for a selection from a list of choices."""
    choices_str = "/".join(choices)
    suffix = f" [{default}]" if default else ""
    while True:
        val = input(f"  {label} ({choices_str}){suffix}: ").strip().lower()
        if not val and default:
            return default
        if val in choices:
            return val
        print(f"    (must be one of: {choices_str})")


def _prompt_yn(label: str, default: bool = True) -> bool:
    """Prompt for yes/no."""
    hint = "Y/n" if default else "y/N"
    val = input(f"  {label} [{hint}]: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


def _prompt_multiline(label: str) -> str:
    """Prompt for multi-line input (end with empty line or Ctrl+D)."""
    print(f"  {label} (enter text, blank line to finish):")
    lines = []
    while True:
        try:
            line = input("  > ")
            if line == "":
                break
            lines.append(line)
        except EOFError:
            break
    return "\n".join(lines)


def _pick_project(db_path=None) -> int | None:
    """Let user pick a project interactively."""
    from ..core.config import get_active_project
    active = get_active_project()
    projs = list_projects(db_path=db_path)
    if not projs:
        print("\n  No projects found. Create one first with 'bb project create' or 'bb wizard project'.\n")
        return None
    if active is not None:
        active_proj = next((p for p in projs if p["id"] == active), None)
        if active_proj:
            if _prompt_yn(f"Use active project [{active_proj['id']}] {active_proj['name']}?"):
                return active
    print("\n  Available projects:")
    for p in projs:
        marker = " ← active" if p["id"] == active else ""
        print(f"    [{p['id']}] {p['name']} ({p['status']}){marker}")
    while True:
        val = input("\n  Project ID: ").strip()
        try:
            pid = int(val)
            if any(p["id"] == pid for p in projs):
                return pid
            print("    (invalid project ID)")
        except ValueError:
            print("    (enter a number)")


def _pick_target(project_id: int, db_path=None) -> int | None:
    """Let user pick a target interactively."""
    tgts = list_targets(project_id, db_path=db_path)
    if not tgts:
        print("\n  No targets in this project. Add one first.")
        return None
    in_scope = [t for t in tgts if t["in_scope"]]
    out_scope = [t for t in tgts if not t["in_scope"]]
    if in_scope:
        print("\n  In-scope targets:")
        for t in in_scope:
            print(f"    [{t['id']}] {t['asset_type']:10s} {t['value']}")
    if out_scope:
        print("\n  Out-of-scope targets:")
        for t in out_scope:
            print(f"    [{t['id']}] {t['asset_type']:10s} {t['value']}  ⚠ OUT-OF-SCOPE")
    val = _prompt("Target ID (or Enter to skip)")
    if val:
        try:
            tid = int(val)
            # Warn if selected target is out of scope
            selected = next((t for t in tgts if t["id"] == tid), None)
            if selected and not selected["in_scope"]:
                print(f"\n  ⚠ Warning: '{selected['value']}' is marked OUT-OF-SCOPE.")
                if not _prompt_yn("Continue anyway?", default=False):
                    return None
            return tid
        except ValueError:
            pass
    return None


# ═══════════════════════════════════════════════════════════════════
# Wizard: New Project
# ═══════════════════════════════════════════════════════════════════

def wizard_project(db_path=None) -> int:
    """Interactive project creation wizard."""
    print("\n═══ New Project Wizard ═══\n")

    name = _prompt("Project / program name", required=True)
    platform = _prompt_choice("Platform", ["hackerone", "bugcrowd", "intigriti", "synack", "private", "other"], "hackerone")
    url = _prompt("Program URL (optional)")
    scope = ""
    if _prompt_yn("Enter scope text now?", default=False):
        scope = _prompt_multiline("Scope")
    rules = ""
    if _prompt_yn("Enter rules of engagement?", default=False):
        rules = _prompt_multiline("Rules of engagement")

    pid = create_project(name=name, platform=platform, program_url=url or None,
                         scope_raw=scope or None, rules=rules or None, db_path=db_path)
    print(f"\n  ✓ Created project [{pid}] {name}")

    # Offer H1 scope import for HackerOne projects
    h1_synced = False
    if platform == "hackerone":
        try:
            from . import hackerone
            auth = hackerone.check_auth()
            if auth.get("valid"):
                if _prompt_yn("Import scope & targets from HackerOne?", default=True):
                    handle = _prompt("H1 program handle", default=name.replace(" ", "_").lower())
                    try:
                        result = hackerone.sync_scope(pid, handle, db_path=db_path)
                        nt = result.get("new_targets", 0)
                        nr = result.get("new_rules", 0)
                        print(f"  ✓ Imported {nt} target(s) and {nr} scope rule(s) from H1")
                        h1_synced = True
                    except Exception as e:
                        print(f"  ✗ H1 import failed: {e}")
                        print("  Falling back to manual entry...")
        except Exception:
            pass  # H1 not configured, skip silently

    if not h1_synced:
        # Offer to define scope rules
        if _prompt_yn("Define scope rules now?", default=True):
            print("\n  Enter scope patterns one per line (wildcards like *.example.com, CIDRs, exact).")
            print("  Prefix with ! to exclude. Blank line when done.\n")
            lines = []
            while True:
                try:
                    line = input("  scope> ").strip()
                    if not line:
                        break
                    lines.append(line)
                except EOFError:
                    break
            if lines:
                from .scope import import_from_text
                result = import_from_text(pid, "\n".join(lines), source="wizard", db_path=db_path)
                added = result.get("added", 0)
                print(f"  ✓ Added {added} scope rule(s)")

        # Offer to add targets immediately
        if _prompt_yn("Add targets now?"):
            while True:
                wizard_target(project_id=pid, db_path=db_path)
                if not _prompt_yn("Add another target?"):
                    break

    print(f"\n✅ Project [{pid}] is ready. Start with 'bb recon run' or 'bb workflow run'.\n")
    return pid


# ═══════════════════════════════════════════════════════════════════
# Wizard: Add Target
# ═══════════════════════════════════════════════════════════════════

def wizard_target(project_id: int = None, db_path=None) -> int:
    """Interactive target addition wizard."""
    if not project_id:
        print("\n═══ Add Target Wizard ═══\n")
        project_id = _pick_project(db_path)
        if not project_id:
            return 0

    value = _prompt("Target value (domain, IP, URL, etc.)", required=True)
    asset_type = _prompt_choice("Asset type", sorted(VALID_ASSET_TYPES), "domain")
    tier = _prompt_choice("Priority tier", ["critical", "high", "medium", "low"], "medium")
    in_scope = _prompt_yn("In scope?", default=True)
    note_text = _prompt("Notes (optional)")

    # Auto-check against scope rules if they exist
    rules = list_rules(project_id, db_path=db_path)
    if rules:
        result = check_scope(project_id, value, db_path=db_path)
        if result["in_scope"] is True:
            matched = result.get("matched_rule")
            rule_info = f" (rule #{matched['id']}: {matched['pattern']})" if matched else ""
            print(f"  \u2713 Scope check: IN-SCOPE{rule_info}")
            in_scope = True
        elif result["in_scope"] is False:
            matched = result.get("matched_rule")
            if matched:
                rule_info = f" (rule #{matched['id']}: {matched['rule_type']} {matched['pattern']})"
            else:
                rule_info = " (no matching include rule)"
            print(f"  \u26a0 Scope check: OUT-OF-SCOPE{rule_info}")
            in_scope = False
        # else: no matching rule, keep user's choice

    tid = add_target(project_id, asset_type, value, in_scope=in_scope,
                     tier=tier, notes=note_text or None, db_path=db_path)
    print(f"  ✓ Added target [{tid}] {value}")
    return tid


# ═══════════════════════════════════════════════════════════════════
# Wizard: New Vulnerability (with template support)
# ═══════════════════════════════════════════════════════════════════

def wizard_vuln(db_path=None) -> int:
    """
    Interactive vulnerability creation wizard.

    Offers to pick from the knowledge base for pre-filled fields,
    then prompts for target-specific details.
    """
    print("\n═══ New Finding Wizard ═══\n")

    # Pick project
    project_id = _pick_project(db_path)
    if not project_id:
        return 0

    # Pick target (optional)
    target_id = _pick_target(project_id, db_path)

    # Template or manual?
    use_template = _prompt_yn("Use a vulnerability template?", default=True)

    if use_template:
        return _wizard_vuln_from_template(project_id, target_id, db_path)
    else:
        return _wizard_vuln_manual(project_id, target_id, db_path)


def _wizard_vuln_from_template(project_id: int, target_id: int | None,
                                db_path=None) -> int:
    """Create a vuln from a knowledge base template."""
    # Show template picker
    template = _pick_template()
    if not template:
        print("  No template selected. Switching to manual entry.\n")
        return _wizard_vuln_manual(project_id, target_id, db_path)

    # Get target-specific details to fill placeholders
    print(f"\n  Selected: {template['key']} — {template['title']}")
    print(f"  Now fill in the target-specific details:\n")

    endpoint = _prompt("Endpoint / URL (e.g., /api/search)", required=True)
    parameter = _prompt("Vulnerable parameter (e.g., q, id, url)")
    target_name = _prompt("Target / domain name")

    # Fill template
    filled = fill_template(
        template["key"],
        target=target_name or "",
        endpoint=endpoint,
        parameter=parameter or "",
    )

    # Show what we got and allow edits
    print(f"\n  --- Pre-filled from template ---")
    print(f"  Title:       {filled['title']}")
    print(f"  Severity:    {severity_color(filled['severity'])}")
    print(f"  CVSS:        {filled['cvss_score']} ({filled['cvss_vector']})")
    print(f"  CWE:         {filled['cwe']}")
    print(f"  OWASP:       {filled['owasp']}")
    print(f"  Type:        {filled['vuln_type']}")
    print()

    # Allow overrides
    if _prompt_yn("Customize any pre-filled fields?", default=False):
        new_title = _prompt(f"Title", default=filled["title"])
        filled["title"] = new_title
        new_sev = _prompt(f"Severity", default=filled["severity"])
        filled["severity"] = new_sev
        if _prompt_yn("Edit description?", default=False):
            filled["description"] = _prompt_multiline("Description") or filled["description"]
        if _prompt_yn("Edit impact?", default=False):
            filled["impact"] = _prompt_multiline("Impact") or filled["impact"]
        if _prompt_yn("Edit remediation?", default=False):
            filled["remediation"] = _prompt_multiline("Remediation") or filled["remediation"]

    # Reproduction steps (always target-specific)
    print("\n  Reproduction steps are always specific to your finding:")
    reproduction = _prompt_multiline("Steps to reproduce")

    # HTTP request/response (optional)
    request = ""
    response = ""
    if _prompt_yn("Add HTTP request/response?", default=False):
        request = _prompt_multiline("HTTP Request")
        response = _prompt_multiline("HTTP Response (relevant excerpt)")

    # Build references string for description
    ref_text = ""
    if filled.get("references"):
        ref_text = "\n\n### References\n\n"
        for ref in filled["references"]:
            ref_text += f"- {ref}\n"
        ref_text += f"\n**CWE:** {filled['cwe']}\n"
        ref_text += f"**OWASP:** {filled['owasp']}\n"

    # Create the vuln
    vid = create_vuln(
        project_id=project_id,
        title=filled["title"],
        severity=filled["severity"],
        vuln_type=filled["vuln_type"],
        target_id=target_id,
        description=filled["description"] + ref_text,
        impact=filled["impact"],
        reproduction=reproduction or None,
        request=request or None,
        response=response or None,
        remediation=filled["remediation"],
        cvss_score=filled["cvss_score"],
        cvss_vector=filled["cvss_vector"],
        db_path=db_path,
    )

    print(f"\n  ✓ Created finding [{vid}] {filled['title']} ({filled['severity'].upper()})")
    print(f"    CWE: {filled['cwe']} | OWASP: {filled['owasp']} | CVSS: {filled['cvss_score']}")

    # Check for potential duplicates
    dupes = find_duplicates(vid, db_path)
    if dupes:
        print(f"\n  ⚠ Potential duplicate(s) found:")
        for d in dupes[:5]:
            print(f"    [{d['id']}] {d['title'][:60]} ({d['severity']}, {d['status']})")
        print(f"    Use 'bb vuln merge {vid} <target_id>' to merge if these are the same.")

    # Add evidence?
    if _prompt_yn("Attach evidence file (screenshot, PoC, etc.)?", default=False):
        ev_path = _prompt("File path")
        if ev_path:
            try:
                add_evidence(vid, ev_path, db_path)
                print(f"  ✓ Evidence attached: {ev_path}")
            except ValueError as e:
                print(f"  ⚠ {e}")

    # Add a note?
    if _prompt_yn("Add a note about this finding?", default=False):
        note_text = _prompt_multiline("Note")
        if note_text:
            create_note(content=note_text, project_id=project_id,
                        vuln_id=vid, title=f"Note on: {filled['title']}", db_path=db_path)
            print("  ✓ Note added")

    print(f"\n✅ Finding [{vid}] recorded. Generate a report with: bb report vuln {vid}\n")
    return vid


def _wizard_vuln_manual(project_id: int, target_id: int | None,
                        db_path=None) -> int:
    """Create a vuln with fully manual entry."""
    print("\n  Manual vulnerability entry:\n")

    title = _prompt("Title", required=True)
    severity = _prompt_choice("Severity", ["critical", "high", "medium", "low", "informational"], "medium")
    vuln_type = _prompt(f"Vuln type ({'/'.join(sorted(list(VALID_VULN_TYPES)[:8]))}... or Enter to skip)")

    description = _prompt_multiline("Description")
    impact = _prompt_multiline("Impact")
    reproduction = _prompt_multiline("Reproduction steps")

    request = ""
    response = ""
    if _prompt_yn("Add HTTP request/response?", default=False):
        request = _prompt_multiline("HTTP Request")
        response = _prompt_multiline("HTTP Response")

    remediation = _prompt_multiline("Remediation advice")

    cvss = None
    cvss_str = _prompt("CVSS score (e.g., 7.5, or Enter to skip)")
    if cvss_str:
        try:
            cvss = float(cvss_str)
        except ValueError:
            pass

    vid = create_vuln(
        project_id=project_id,
        title=title,
        severity=severity,
        vuln_type=vuln_type or None,
        target_id=target_id,
        description=description or None,
        impact=impact or None,
        reproduction=reproduction or None,
        request=request or None,
        response=response or None,
        remediation=remediation or None,
        cvss_score=cvss,
        db_path=db_path,
    )

    print(f"\n  ✓ Created finding [{vid}] {title} ({severity.upper()})")

    # Check for potential duplicates
    dupes = find_duplicates(vid, db_path)
    if dupes:
        print(f"\n  ⚠ Potential duplicate(s) found:")
        for d in dupes[:5]:
            print(f"    [{d['id']}] {d['title'][:60]} ({d['severity']}, {d['status']})")
        print(f"    Use 'bb vuln merge {vid} <target_id>' to merge if these are the same.")

    # Add evidence?
    if _prompt_yn("Attach evidence file?", default=False):
        ev_path = _prompt("File path")
        if ev_path:
            try:
                add_evidence(vid, ev_path, db_path)
                print(f"  ✓ Evidence attached: {ev_path}")
            except ValueError as e:
                print(f"  ⚠ {e}")

    print(f"\n✅ Finding [{vid}] recorded. Generate a report with: bb report vuln {vid}\n")
    return vid


# ═══════════════════════════════════════════════════════════════════
# Template picker
# ═══════════════════════════════════════════════════════════════════

def _pick_template() -> dict | None:
    """Interactive template selection — browse or search."""
    print("\n  Vulnerability Knowledge Base")
    print("  Choose how to find a template:\n")
    print("    [1] Browse by OWASP category")
    print("    [2] Search by keyword")
    print("    [3] List all templates")
    print("    [4] Skip (manual entry)")

    choice = _prompt("Choice", default="1")

    if choice == "1":
        return _browse_by_category()
    elif choice == "2":
        return _search_template()
    elif choice == "3":
        return _list_all_templates()
    else:
        return None


def _browse_by_category() -> dict | None:
    """Browse templates grouped by OWASP category."""
    categories = get_templates_by_category()
    cat_list = sorted(categories.keys())

    print("\n  OWASP Categories:\n")
    for i, cat in enumerate(cat_list, 1):
        count = len(categories[cat])
        print(f"    [{i}] {cat} ({count} templates)")

    choice = _prompt("Category number")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(cat_list):
            cat = cat_list[idx]
            templates = categories[cat]
            return _show_template_list(templates)
    except (ValueError, IndexError):
        pass
    return None


def _search_template() -> dict | None:
    """Search templates by keyword."""
    query = _prompt("Search keyword (e.g., xss, injection, access)")
    if not query:
        return None
    results = search_templates(query)
    if not results:
        print("  No templates matched. Try a different keyword.")
        return None
    return _show_template_list(results)


def _list_all_templates() -> dict | None:
    """List all templates and let user pick."""
    all_templates = list(VULN_TEMPLATES.values())
    return _show_template_list(all_templates)


def _show_template_list(templates: list[dict]) -> dict | None:
    """Show a list of templates and let user pick one."""
    print(f"\n  Available templates ({len(templates)}):\n")
    for i, t in enumerate(templates, 1):
        sev = t.get("severity", "?").upper()
        cwe = t.get("cwe", "")
        print(f"    [{i:2d}] {t['key']:30s} {sev:14s} {cwe}")

    choice = _prompt("Template number (or Enter to go back)")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(templates):
            return templates[idx]
    except (ValueError, IndexError):
        pass
    return None


# ═══════════════════════════════════════════════════════════════════
# Quick Vuln — fastest path using templates
# ═══════════════════════════════════════════════════════════════════

def quick_vuln(template_key: str, project_id: int, endpoint: str,
               parameter: str = "", target: str = "", target_id: int = None,
               reproduction: str = None, request: str = None,
               db_path=None) -> int:
    """
    Fastest way to log a vuln — one-liner with template key.

    Usage in CLI:
        bb vuln quick <template_key> <project_id> <endpoint> [options]

    All descriptions, impact, remediation, CVSS, CWE, OWASP are
    auto-filled from the knowledge base.
    """
    filled = fill_template(template_key, target=target, endpoint=endpoint,
                           parameter=parameter)
    if not filled:
        raise ValueError(f"Unknown template '{template_key}'. Use 'bb templates list' to see available templates.")

    ref_text = ""
    if filled.get("references"):
        ref_text = "\n\n### References\n\n"
        for ref in filled["references"]:
            ref_text += f"- {ref}\n"
        ref_text += f"\n**CWE:** {filled['cwe']}\n"
        ref_text += f"**OWASP:** {filled['owasp']}\n"

    vid = create_vuln(
        project_id=project_id,
        title=filled["title"],
        severity=filled["severity"],
        vuln_type=filled["vuln_type"],
        target_id=target_id,
        description=filled["description"] + ref_text,
        impact=filled["impact"],
        reproduction=reproduction,
        request=request,
        remediation=filled["remediation"],
        cvss_score=filled["cvss_score"],
        cvss_vector=filled["cvss_vector"],
        db_path=db_path,
    )

    # Warn about potential duplicates (printed to stderr so scripts can ignore)
    dupes = find_duplicates(vid, db_path)
    if dupes:
        import sys
        print(f"  ⚠ {len(dupes)} potential duplicate(s) — use 'bb vuln duplicates {vid}' to review.",
              file=sys.stderr)

    return vid
