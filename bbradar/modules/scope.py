"""
Scope rules engine.

Provides pattern-based scope matching for bug bounty programs:
  - Wildcard domains:  *.example.com, *.api.example.com
  - Exact matches:     admin.example.com, 10.0.0.1
  - CIDR ranges:       10.0.0.0/24, 192.168.1.0/16
  - URL path patterns: https://example.com/api/*
  - Regex patterns:    ^.*\\.staging\\.example\\.com$

Rules can be include or exclude, with priority ordering.
Excludes win over includes at the same priority level.
"""

import ipaddress
import json
import re
from fnmatch import fnmatch
from urllib.parse import urlparse

from ..core.database import get_connection
from ..core.audit import log_action
from ..core.utils import timestamp_now


# ═══════════════════════════════════════════════════════════════════
# Rule CRUD
# ═══════════════════════════════════════════════════════════════════

def add_rule(project_id: int, pattern: str, rule_type: str = "include",
             pattern_type: str = None, asset_category: str = None,
             priority: int = 0, notes: str = None, source: str = "manual",
             db_path=None) -> int:
    """
    Add a scope rule.  Auto-detects pattern_type if not specified.
    Returns the rule ID.
    """
    rule_type = rule_type.lower()
    if rule_type not in ("include", "exclude"):
        raise ValueError("rule_type must be 'include' or 'exclude'")

    pattern = pattern.strip()
    if not pattern:
        raise ValueError("Pattern cannot be empty")

    if not pattern_type:
        pattern_type = _detect_pattern_type(pattern)

    if pattern_type not in ("wildcard", "cidr", "regex", "exact"):
        raise ValueError(f"Invalid pattern_type '{pattern_type}'")

    # Validate pattern compiles correctly
    _validate_pattern(pattern, pattern_type)

    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO scope_rules
               (project_id, rule_type, pattern_type, pattern, asset_category, priority, notes, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (project_id, rule_type, pattern_type, pattern,
             asset_category, priority, notes, source),
        )
        rid = cursor.lastrowid

    log_action("created", "scope_rule", rid,
               {"project_id": project_id, "rule_type": rule_type, "pattern": pattern}, db_path)
    return rid


def bulk_add_rules(project_id: int, rules: list[dict], source: str = "import",
                   db_path=None) -> int:
    """
    Add multiple rules at once.  Each dict should have at minimum 'pattern'
    and optionally 'rule_type', 'pattern_type', 'asset_category', 'priority', 'notes'.
    Returns number of rules added.
    """
    count = 0
    with get_connection(db_path) as conn:
        for r in rules:
            pattern = r.get("pattern", "").strip()
            if not pattern:
                continue
            rule_type = r.get("rule_type", "include").lower()
            if rule_type not in ("include", "exclude"):
                continue
            pattern_type = r.get("pattern_type") or _detect_pattern_type(pattern)
            try:
                _validate_pattern(pattern, pattern_type)
            except ValueError:
                continue
            conn.execute(
                """INSERT INTO scope_rules
                   (project_id, rule_type, pattern_type, pattern, asset_category, priority, notes, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (project_id, rule_type, pattern_type, pattern,
                 r.get("asset_category"), r.get("priority", 0),
                 r.get("notes"), source),
            )
            count += 1

    log_action("bulk_created", "scope_rule", None,
               {"project_id": project_id, "count": count, "source": source}, db_path)
    return count


def list_rules(project_id: int, rule_type: str = None, db_path=None) -> list[dict]:
    """List scope rules for a project, ordered by priority then type."""
    with get_connection(db_path) as conn:
        query = "SELECT * FROM scope_rules WHERE project_id = ?"
        params: list = [project_id]
        if rule_type:
            query += " AND rule_type = ?"
            params.append(rule_type)
        query += " ORDER BY priority ASC, rule_type DESC, id ASC"
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_rule(rule_id: int, db_path=None) -> dict | None:
    """Get a single scope rule."""
    with get_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM scope_rules WHERE id = ?", (rule_id,)).fetchone()
    return dict(row) if row else None


def update_rule(rule_id: int, db_path=None, **kwargs) -> bool:
    """Update a scope rule."""
    allowed = {"rule_type", "pattern_type", "pattern", "asset_category", "priority", "notes"}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return False
    if "pattern" in updates and "pattern_type" in updates:
        _validate_pattern(updates["pattern"], updates["pattern_type"])
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [rule_id]
    with get_connection(db_path) as conn:
        conn.execute(f"UPDATE scope_rules SET {set_clause} WHERE id = ?", values)
    log_action("updated", "scope_rule", rule_id, updates, db_path)
    return True


def delete_rule(rule_id: int, db_path=None) -> bool:
    """Delete a scope rule."""
    with get_connection(db_path) as conn:
        conn.execute("DELETE FROM scope_rules WHERE id = ?", (rule_id,))
    log_action("deleted", "scope_rule", rule_id, db_path=db_path)
    return True


def clear_rules(project_id: int, db_path=None) -> int:
    """Delete all scope rules for a project.  Returns count deleted."""
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM scope_rules WHERE project_id = ?", (project_id,))
        count = cursor.rowcount
    log_action("cleared", "scope_rule", None,
               {"project_id": project_id, "count": count}, db_path)
    return count


# ═══════════════════════════════════════════════════════════════════
# Scope Checking
# ═══════════════════════════════════════════════════════════════════

def check_scope(project_id: int, value: str, db_path=None) -> dict:
    """
    Check if a value is in scope for the project.

    Returns:
        {
            "in_scope": bool,
            "matched_rule": dict | None,    — the rule that determined the result
            "reason": str,                  — human-readable explanation
            "all_matches": list[dict],      — all rules that matched
        }

    Evaluation logic:
        1. Evaluate all rules against the value
        2. Group matches by priority level
        3. At each priority level, exclude wins over include
        4. Highest priority matching rule determines outcome
        5. If no rules match → default to out-of-scope (explicit allowlist model)
    """
    rules = list_rules(project_id, db_path=db_path)
    if not rules:
        return {
            "in_scope": None,
            "matched_rule": None,
            "reason": "No scope rules defined for this project",
            "all_matches": [],
        }

    value = value.strip()
    matches = []

    for rule in rules:
        if _matches(rule, value):
            matches.append(rule)

    if not matches:
        return {
            "in_scope": False,
            "matched_rule": None,
            "reason": f"'{value}' did not match any scope rule",
            "all_matches": [],
        }

    # Sort by priority (highest last) — highest priority wins
    matches.sort(key=lambda r: r["priority"])

    # At the highest priority level, exclude wins
    top_priority = matches[-1]["priority"]
    top_matches = [m for m in matches if m["priority"] == top_priority]

    # If any exclude at top priority, out of scope
    excludes = [m for m in top_matches if m["rule_type"] == "exclude"]
    if excludes:
        rule = excludes[0]
        return {
            "in_scope": False,
            "matched_rule": rule,
            "reason": f"Excluded by rule #{rule['id']}: {rule['rule_type']} {rule['pattern']}",
            "all_matches": matches,
        }

    # Otherwise use first include
    includes = [m for m in top_matches if m["rule_type"] == "include"]
    if includes:
        rule = includes[0]
        return {
            "in_scope": True,
            "matched_rule": rule,
            "reason": f"Included by rule #{rule['id']}: {rule['pattern']}",
            "all_matches": matches,
        }

    return {
        "in_scope": False,
        "matched_rule": None,
        "reason": f"'{value}' did not match any include rule",
        "all_matches": matches,
    }


def check_scope_batch(project_id: int, values: list[str],
                      db_path=None) -> list[dict]:
    """Check multiple values against scope rules.  Returns list of check results."""
    rules = list_rules(project_id, db_path=db_path)
    results = []
    for val in values:
        # Inline check to avoid re-fetching rules each time
        val = val.strip()
        matches = [r for r in rules if _matches(r, val)]

        if not rules:
            results.append({"value": val, "in_scope": None, "reason": "No rules defined"})
        elif not matches:
            results.append({"value": val, "in_scope": False, "reason": "No matching rule"})
        else:
            matches.sort(key=lambda r: r["priority"])
            top_priority = matches[-1]["priority"]
            top_matches = [m for m in matches if m["priority"] == top_priority]
            excludes = [m for m in top_matches if m["rule_type"] == "exclude"]
            if excludes:
                results.append({"value": val, "in_scope": False,
                                "reason": f"Excluded: {excludes[0]['pattern']}"})
            else:
                includes = [m for m in top_matches if m["rule_type"] == "include"]
                if includes:
                    results.append({"value": val, "in_scope": True,
                                    "reason": f"Included: {includes[0]['pattern']}"})
                else:
                    results.append({"value": val, "in_scope": False, "reason": "No include match"})

    return results


def validate_targets(project_id: int, db_path=None) -> dict:
    """
    Validate all existing targets against scope rules.

    Returns:
        {
            "total": int,
            "correct": int,        — in_scope flag matches rules
            "mismatches": list,    — targets whose in_scope doesn't match rules
            "unmatched": list,     — targets not matching any rule
        }
    """
    from ..modules import targets

    rules = list_rules(project_id, db_path=db_path)
    if not rules:
        return {"total": 0, "correct": 0, "mismatches": [], "unmatched": [],
                "message": "No scope rules defined"}

    all_targets = targets.list_targets(project_id, db_path=db_path)
    correct = 0
    mismatches = []
    unmatched = []

    for t in all_targets:
        result = check_scope(project_id, t["value"], db_path=db_path)
        if result["in_scope"] is None:
            unmatched.append(t)
        elif result["in_scope"] != bool(t["in_scope"]):
            mismatches.append({
                "target": t,
                "expected": result["in_scope"],
                "current": bool(t["in_scope"]),
                "reason": result["reason"],
            })
        else:
            correct += 1

    return {
        "total": len(all_targets),
        "correct": correct,
        "mismatches": mismatches,
        "unmatched": unmatched,
    }


def auto_scope_targets(project_id: int, dry_run: bool = False,
                       db_path=None) -> dict:
    """
    Automatically set in_scope on targets based on scope rules.
    Returns summary of changes made.
    """
    from ..modules import targets

    validation = validate_targets(project_id, db_path=db_path)
    changes = []

    for m in validation["mismatches"]:
        t = m["target"]
        new_scope = m["expected"]
        if not dry_run:
            targets.update_target(t["id"], in_scope=new_scope, db_path=db_path)
        changes.append({
            "target_id": t["id"],
            "value": t["value"],
            "old_scope": m["current"],
            "new_scope": new_scope,
            "reason": m["reason"],
        })

    return {
        "total_targets": validation["total"],
        "correct": validation["correct"],
        "changes": changes,
        "unmatched": len(validation["unmatched"]),
    }


def scope_overview(project_id: int, db_path=None) -> dict:
    """
    Generate a scope overview for a project.
    Returns structured data for display.
    """
    rules = list_rules(project_id, db_path=db_path)
    includes = [r for r in rules if r["rule_type"] == "include"]
    excludes = [r for r in rules if r["rule_type"] == "exclude"]

    from ..modules import targets
    all_targets = targets.list_targets(project_id, db_path=db_path)
    in_scope_targets = [t for t in all_targets if t["in_scope"]]
    out_scope_targets = [t for t in all_targets if not t["in_scope"]]

    return {
        "rules_total": len(rules),
        "includes": includes,
        "excludes": excludes,
        "targets_total": len(all_targets),
        "targets_in_scope": len(in_scope_targets),
        "targets_out_scope": len(out_scope_targets),
        "in_scope_targets": in_scope_targets,
        "out_scope_targets": out_scope_targets,
    }


# ═══════════════════════════════════════════════════════════════════
# Scope Import
# ═══════════════════════════════════════════════════════════════════

def import_from_text(project_id: int, text: str, source: str = "import",
                     db_path=None) -> dict:
    """
    Import scope rules from text.  Supports multiple formats:

    1. Simple list (one pattern per line):
       *.example.com
       !admin.example.com
       10.0.0.0/24

    2. Labeled format:
       IN: *.example.com
       OUT: admin.example.com
       INCLUDE: api.example.com
       EXCLUDE: staging.example.com

    3. Markdown table:
       | Asset          | Type   |
       | *.example.com  | In     |
       | admin.example  | Out    |

    Lines starting with # are comments.  Empty lines are skipped.
    """
    rules = []
    skipped_lines = []
    for line_num, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Skip markdown table headers/separators
        if line.startswith("|") and ("---" in line or "Asset" in line or "Type" in line):
            continue

        rule = _parse_scope_line(line)
        if rule:
            rules.append(rule)
        else:
            skipped_lines.append((line_num, line))

    if not rules:
        return {"added": 0, "errors": 0, "skipped": skipped_lines,
                "message": "No valid scope rules found in input"}

    count = bulk_add_rules(project_id, rules, source=source, db_path=db_path)
    result = {"added": count, "total_parsed": len(rules)}
    if skipped_lines:
        result["skipped"] = skipped_lines
        result["skipped_count"] = len(skipped_lines)
    return result


def import_from_file(project_id: int, filepath: str, db_path=None) -> dict:
    """Import scope rules from a file.  Auto-detects format."""
    from pathlib import Path
    p = Path(filepath)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    data = p.read_text(errors="replace")

    # Try JSON first (HackerOne / Bugcrowd API format)
    result = _try_json_import(project_id, data, db_path)
    if result:
        return result

    # Fall back to text format
    return import_from_text(project_id, data, source="import", db_path=db_path)


def import_hackerone(project_id: int, data: str, db_path=None) -> dict:
    """
    Import scope from HackerOne JSON format.

    Expected structure (from HackerOne API):
    {
        "relationships": {
            "structured_scopes": {
                "data": [
                    {
                        "attributes": {
                            "asset_identifier": "*.example.com",
                            "asset_type": "URL",
                            "eligible_for_bounty": true,
                            "eligible_for_submission": true,
                            "instruction": "notes..."
                        }
                    }
                ]
            }
        }
    }

    Also supports the flat array format:
    [{"asset_identifier": "*.example.com", "asset_type": "URL", ...}]
    """
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return {"added": 0, "error": "Invalid JSON"}

    items = _extract_hackerone_scopes(parsed)
    if not items:
        return {"added": 0, "error": "No scope entries found in HackerOne format"}

    rules = []
    for item in items:
        identifier = item.get("asset_identifier", "").strip()
        if not identifier:
            continue

        asset_type = (item.get("asset_type", "") or "").lower()
        eligible = item.get("eligible_for_submission", True)
        instruction = item.get("instruction", "")

        rule_type = "include" if eligible else "exclude"
        asset_category = _h1_asset_type(asset_type)

        rules.append({
            "pattern": identifier,
            "rule_type": rule_type,
            "asset_category": asset_category,
            "notes": instruction[:500] if instruction else None,
        })

    count = bulk_add_rules(project_id, rules, source="hackerone", db_path=db_path)
    return {"added": count, "source": "hackerone", "total_parsed": len(rules)}


def import_bugcrowd(project_id: int, data: str, db_path=None) -> dict:
    """
    Import scope from Bugcrowd JSON format.

    Expected structure:
    {
        "targets": {
            "in_scope": [
                {"target": "*.example.com", "type": "website"}
            ],
            "out_of_scope": [
                {"target": "admin.example.com", "type": "website"}
            ]
        }
    }

    Also supports flat array:
    {"in_scope": [...], "out_of_scope": [...]}
    """
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return {"added": 0, "error": "Invalid JSON"}

    in_scope = []
    out_scope = []

    if "targets" in parsed:
        container = parsed["targets"]
    else:
        container = parsed

    if isinstance(container, dict):
        in_scope = container.get("in_scope", container.get("in-scope", []))
        out_scope = container.get("out_of_scope", container.get("out-of-scope", []))

    rules = []
    for item in in_scope:
        target = item.get("target", item.get("name", "")).strip()
        if target:
            rules.append({
                "pattern": target,
                "rule_type": "include",
                "asset_category": _bc_asset_type(item.get("type", "")),
                "notes": item.get("description", ""),
            })

    for item in out_scope:
        target = item.get("target", item.get("name", "")).strip()
        if target:
            rules.append({
                "pattern": target,
                "rule_type": "exclude",
                "asset_category": _bc_asset_type(item.get("type", "")),
                "notes": item.get("description", ""),
            })

    count = bulk_add_rules(project_id, rules, source="bugcrowd", db_path=db_path)
    return {"added": count, "source": "bugcrowd", "total_parsed": len(rules)}


# ═══════════════════════════════════════════════════════════════════
# Internal pattern matching
# ═══════════════════════════════════════════════════════════════════

def _matches(rule: dict, value: str) -> bool:
    """Check if a value matches a rule's pattern."""
    pattern = rule["pattern"]
    pattern_type = rule["pattern_type"]
    category = rule.get("asset_category")

    # If rule has asset_category, do basic category filtering
    if category:
        val_category = _guess_category(value)
        if val_category and category != "general" and val_category != category:
            return False

    value_lower = value.lower().strip()
    pattern_lower = pattern.lower().strip()

    if pattern_type == "exact":
        return value_lower == pattern_lower

    elif pattern_type == "wildcard":
        return _wildcard_match(pattern_lower, value_lower)

    elif pattern_type == "cidr":
        return _cidr_match(pattern, value)

    elif pattern_type == "regex":
        try:
            return bool(re.search(pattern, value, re.IGNORECASE))
        except re.error:
            return False

    return False


def _wildcard_match(pattern: str, value: str) -> bool:
    """
    Match wildcard patterns against values.

    Handles:
      *.example.com   → matches sub.example.com, a.b.example.com
      example.com     → matches example.com exactly
      *.example.com/* → matches sub.example.com/path
      https://*.example.com → matches https://sub.example.com
    """
    # Strip protocol for comparison if present in either
    pattern_clean = _strip_protocol(pattern)
    value_clean = _strip_protocol(value)

    # Direct fnmatch
    if fnmatch(value_clean, pattern_clean):
        return True

    # Also try matching just the hostname part
    pattern_host = _extract_host(pattern_clean)
    value_host = _extract_host(value_clean)

    if pattern_host and value_host:
        if fnmatch(value_host, pattern_host):
            return True

    # *.example.com should match example.com itself
    if pattern_clean.startswith("*."):
        base = pattern_clean[2:]
        if value_clean == base or value_clean.endswith("." + base):
            return True

    return False


def _cidr_match(pattern: str, value: str) -> bool:
    """Check if a value (IP or hostname) falls within a CIDR range."""
    try:
        network = ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return False

    # Extract IP from value
    ip_str = value.strip()
    ip_str = _strip_protocol(ip_str)
    ip_str = _extract_host(ip_str)

    # Remove port
    if ":" in ip_str and not ip_str.startswith("["):
        ip_str = ip_str.rsplit(":", 1)[0]

    try:
        addr = ipaddress.ip_address(ip_str)
        return addr in network
    except ValueError:
        return False


def _detect_pattern_type(pattern: str) -> str:
    """Auto-detect the pattern type from the pattern string."""
    pattern = pattern.strip()

    # CIDR notation
    if "/" in pattern:
        try:
            ipaddress.ip_network(pattern, strict=False)
            return "cidr"
        except ValueError:
            pass

    # Regex (starts with ^ or contains unescaped regex metacharacters)
    if pattern.startswith("^") or pattern.endswith("$"):
        return "regex"
    # Check for regex-specific syntax (but not wildcards)
    if re.search(r'(?<!\\)[(\[|+?{}]', pattern):
        return "regex"

    # Wildcard (contains * or ?)
    if "*" in pattern or "?" in pattern:
        return "wildcard"

    # Default to exact
    return "exact"


def _validate_pattern(pattern: str, pattern_type: str):
    """Validate that a pattern is syntactically correct."""
    if pattern_type == "regex":
        try:
            compiled = re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
        # Basic ReDoS protection: reject patterns with nested quantifiers
        if re.search(r'(\.\*|\.\+|\[.*\])[*+?]\)?[*+?]', pattern):
            raise ValueError(
                "Regex pattern rejected: nested quantifiers may cause catastrophic backtracking"
            )
    elif pattern_type == "cidr":
        try:
            ipaddress.ip_network(pattern, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR pattern: {e}")


def _strip_protocol(val: str) -> str:
    """Remove http:// or https:// prefix."""
    for prefix in ("https://", "http://"):
        if val.startswith(prefix):
            return val[len(prefix):]
    return val


def _extract_host(val: str) -> str:
    """Extract just the hostname from a URL-like string."""
    # Remove path
    if "/" in val:
        val = val.split("/")[0]
    # Remove port
    if ":" in val and not val.startswith("["):
        val = val.rsplit(":", 1)[0]
    return val


def _guess_category(value: str) -> str | None:
    """Guess the asset category of a value."""
    value = value.strip()
    clean = _strip_protocol(value)

    # URL
    if value.startswith("http://") or value.startswith("https://"):
        return "url"

    # IP address or CIDR
    try:
        ipaddress.ip_address(clean.split(":")[0])
        return "ip"
    except ValueError:
        pass

    try:
        ipaddress.ip_network(clean, strict=False)
        return "ip"
    except ValueError:
        pass

    # Domain-like
    if "." in clean and not "/" in clean:
        return "domain"

    return None


def _parse_scope_line(line: str) -> dict | None:
    """Parse a single line of scope text into a rule dict."""
    line = line.strip()
    if not line:
        return None

    # Markdown table row: | pattern | type |
    if line.startswith("|") and line.endswith("|"):
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) >= 1 and cells[0]:
            pattern = cells[0]
            rule_type = "include"
            if len(cells) >= 2:
                type_cell = cells[1].lower()
                if any(w in type_cell for w in ("out", "exclude", "no")):
                    rule_type = "exclude"
            return {"pattern": pattern, "rule_type": rule_type}
        return None

    # Labeled format:  IN: pattern  or  OUT: pattern  or  INCLUDE: pattern
    label_match = re.match(
        r'^(IN|OUT|INCLUDE|EXCLUDE|IN[\s-]?SCOPE|OUT[\s-]?(?:OF[\s-]?)?SCOPE)\s*:\s*(.+)',
        line, re.IGNORECASE)
    if label_match:
        label = label_match.group(1).upper()
        pattern = label_match.group(2).strip()
        rule_type = "exclude" if "OUT" in label or "EXCLUDE" in label else "include"
        return {"pattern": pattern, "rule_type": rule_type}

    # Negation prefix:  !pattern  or  -pattern
    if line.startswith("!") or line.startswith("-"):
        return {"pattern": line[1:].strip(), "rule_type": "exclude"}

    # Plain pattern (include by default)
    return {"pattern": line, "rule_type": "include"}


def _extract_hackerone_scopes(data) -> list[dict]:
    """Extract scope items from various HackerOne JSON structures."""
    # Nested API format
    if isinstance(data, dict):
        rel = data.get("relationships", {})
        scopes = rel.get("structured_scopes", {})
        scope_data = scopes.get("data", [])
        if scope_data:
            return [item.get("attributes", item) for item in scope_data
                    if isinstance(item, dict)]

        # Flat scope list
        if "structured_scopes" in data:
            items = data["structured_scopes"]
            if isinstance(items, list):
                return [item.get("attributes", item) for item in items
                        if isinstance(item, dict)]

        # Direct attributes list
        if "data" in data:
            items = data["data"]
            if isinstance(items, list):
                return [item.get("attributes", item) for item in items
                        if isinstance(item, dict)]

    # Array of scope items
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)
                and ("asset_identifier" in item or
                     "attributes" in item and "asset_identifier" in item.get("attributes", {}))]

    return []


def _h1_asset_type(h1_type: str) -> str | None:
    """Map HackerOne asset type to our category."""
    mapping = {
        "url": "url",
        "domain": "domain",
        "wildcard": "domain",
        "cidr": "ip",
        "ip_address": "ip",
        "source_code": None,
        "mobile_application": None,
        "hardware": None,
        "other": None,
    }
    return mapping.get(h1_type.lower())


def _bc_asset_type(bc_type: str) -> str | None:
    """Map Bugcrowd asset type to our category."""
    mapping = {
        "website": "url",
        "api": "url",
        "domain": "domain",
        "android": None,
        "ios": None,
        "hardware": None,
        "other": None,
    }
    return mapping.get(bc_type.lower())


def _try_json_import(project_id: int, data: str, db_path=None) -> dict | None:
    """Try to import as HackerOne or Bugcrowd JSON."""
    data = data.strip()
    if not (data.startswith("{") or data.startswith("[")):
        return None

    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return None

    # Detect format
    if isinstance(parsed, dict):
        # HackerOne
        if ("structured_scopes" in str(parsed.get("relationships", {}))
                or "asset_identifier" in str(parsed)):
            return import_hackerone(project_id, data, db_path)

        # Bugcrowd
        if ("in_scope" in parsed or "in-scope" in parsed or
                ("targets" in parsed and isinstance(parsed["targets"], dict))):
            return import_bugcrowd(project_id, data, db_path)

    # Array of scope items
    if isinstance(parsed, list) and parsed:
        if "asset_identifier" in parsed[0]:
            return import_hackerone(project_id, data, db_path)

    return None
