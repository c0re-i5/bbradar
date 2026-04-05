"""
Parameter classification module.

Classifies discovered parameters by vulnerability affinity — IDOR,
SSRF, SQLi, XSS, path traversal, open redirect, etc.  Uses heuristic
name-matching (no ML, no external calls) so it runs instantly.

Classifications are stored as metadata on existing recon_data rows
and surfaced as suggested test cases for the probe / manual-test
workflows.
"""

import json
import logging
import re

from ..core.database import get_connection
from ..core.audit import log_action
from .recon import list_recon

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# Heuristic rules: { vuln_class: (description, [param patterns]) }
# ═══════════════════════════════════════════════════════════════════

CLASSIFICATION_RULES: dict[str, tuple[str, list[re.Pattern]]] = {
    "idor": (
        "Insecure Direct Object Reference — parameter references an object by ID",
        [re.compile(p, re.IGNORECASE) for p in (
            r"^id$", r"_id$", r"^uid$", r"^user_?id$", r"^account_?id$",
            r"^org_?id$", r"^team_?id$", r"^doc_?id$", r"^file_?id$",
            r"^invoice", r"^order_?id$", r"^ref$", r"^number$",
            r"^profile", r"^customer", r"^object",
        )],
    ),

    "ssrf": (
        "Server-Side Request Forgery — parameter accepts URLs or hostnames",
        [re.compile(p, re.IGNORECASE) for p in (
            r"^url$", r"^uri$", r"^path$", r"^dest$", r"^redirect",
            r"^src$", r"^source$", r"^target$", r"^proxy$",
            r"^feed$", r"^host$", r"^domain$", r"^callback",
            r"^return_?url", r"^next$", r"^goto$", r"^link$",
            r"^webhook", r"^endpoint$",
        )],
    ),

    "sqli": (
        "SQL Injection — parameter likely used in database queries",
        [re.compile(p, re.IGNORECASE) for p in (
            r"^id$", r"^sort$", r"^order$", r"^column$", r"^field$",
            r"^table$", r"^query$", r"^search$", r"^filter$",
            r"^where$", r"^group$", r"^by$", r"^limit$", r"^offset$",
            r"^page$", r"^select$", r"^from$", r"^category",
            r"^dir$", r"^direction$",
        )],
    ),

    "xss": (
        "Cross-Site Scripting — parameter value may be reflected in HTML",
        [re.compile(p, re.IGNORECASE) for p in (
            r"^q$", r"^s$", r"^search", r"^query$", r"^keyword",
            r"^name$", r"^title$", r"^body$", r"^content$",
            r"^message$", r"^comment$", r"^text$", r"^desc",
            r"^label$", r"^value$", r"^input$", r"^error",
            r"^msg$", r"^callback$", r"^html$",
        )],
    ),

    "lfi": (
        "Local File Inclusion / Path Traversal",
        [re.compile(p, re.IGNORECASE) for p in (
            r"^file$", r"^path$", r"^folder$", r"^dir$",
            r"^document$", r"^root$", r"^pg$", r"^style$",
            r"^pdf$", r"^template$", r"^php_path", r"^doc$",
            r"^include$", r"^page$", r"^conf$", r"^log$",
            r"^download$", r"^read$", r"^load$",
        )],
    ),

    "open_redirect": (
        "Open Redirect — parameter controls redirect destination",
        [re.compile(p, re.IGNORECASE) for p in (
            r"^redirect", r"^return", r"^next$", r"^url$",
            r"^rurl$", r"^dest$", r"^destination$", r"^goto$",
            r"^out$", r"^continue$", r"^target$", r"^redir$",
            r"^return_?to$", r"^forward$", r"^ref$",
        )],
    ),

    "rce": (
        "Remote Code Execution — parameter may reach OS or eval",
        [re.compile(p, re.IGNORECASE) for p in (
            r"^cmd$", r"^exec$", r"^command$", r"^execute$",
            r"^ping$", r"^query$", r"^code$", r"^reg$",
            r"^do$", r"^func$", r"^arg$", r"^option$",
            r"^daemon$", r"^process$", r"^step$",
        )],
    ),

    "info_leak": (
        "Information Disclosure — parameter may reveal internal data",
        [re.compile(p, re.IGNORECASE) for p in (
            r"^debug$", r"^test$", r"^verbose$", r"^trace$",
            r"^log$", r"^admin$", r"^env$", r"^mode$",
            r"^show$", r"^dump$", r"^export$", r"^format$",
            r"^raw$",
        )],
    ),
}


def classify_param(param_name: str) -> list[dict]:
    """
    Classify a single parameter name by vulnerability affinity.

    Returns list of {vuln_class, description, confidence} dicts,
    sorted by confidence descending.
    """
    results = []
    name = param_name.strip()
    if not name:
        return results

    for vuln_class, (desc, patterns) in CLASSIFICATION_RULES.items():
        for pat in patterns:
            if pat.search(name):
                # Exact whole-name matches get high confidence
                confidence = "high" if pat.pattern.startswith("^") and pat.pattern.endswith("$") else "medium"
                results.append({
                    "vuln_class": vuln_class,
                    "description": desc,
                    "confidence": confidence,
                })
                break  # One match per class is enough

    return sorted(results, key=lambda r: (0 if r["confidence"] == "high" else 1))


def classify_target(target_id: int, db_path=None) -> dict:
    """
    Classify all discovered parameters for a target.

    Reads parameter-type recon_data, classifies each, and stores
    the classifications as metadata in the raw_output field.

    Returns summary: {total_params, classified, classifications: {class: count}}.
    """
    params = list_recon(target_id=target_id, data_type="parameter", db_path=db_path)

    classified = 0
    class_counts: dict[str, int] = {}
    results_by_param: list[dict] = []

    with get_connection(db_path) as conn:
        for param in params:
            param_name = param["value"]
            # Strip URL context if present, e.g. "page (https://example.com/search)"
            if " (" in param_name:
                param_name = param_name.split(" (")[0]

            hits = classify_param(param_name)
            if hits:
                classified += 1
                for h in hits:
                    class_counts[h["vuln_class"]] = class_counts.get(h["vuln_class"], 0) + 1

                results_by_param.append({
                    "param": param["value"],
                    "recon_id": param["id"],
                    "classifications": hits,
                })

                # Persist classification in raw_output
                meta = json.dumps({"vuln_classes": [h["vuln_class"] for h in hits]})
                try:
                    conn.execute(
                        "UPDATE recon_data SET raw_output = ? WHERE id = ?",
                        (meta, param["id"]),
                    )
                except Exception:
                    logger.debug("Could not update recon_data %d", param["id"])

    log_action("param_classify", "recon", None, {
        "target_id": target_id,
        "total_params": len(params),
        "classified": classified,
        "classes": class_counts,
    }, db_path)

    return {
        "total_params": len(params),
        "classified": classified,
        "classifications": class_counts,
        "details": results_by_param,
    }


def suggest_tests(target_id: int, db_path=None) -> list[dict]:
    """
    Generate suggested test cases from classified parameters.

    Returns list of {param, url_context, vuln_class, test_suggestion}
    suitable for display or export.
    """
    result = classify_target(target_id, db_path=db_path)
    suggestions = []

    test_templates = {
        "idor": "Try incrementing/decrementing the ID value. Test with another user's session.",
        "ssrf": "Supply internal URLs (169.254.169.254, localhost, 127.0.0.1). Try URL schemes (file://, dict://).",
        "sqli": "Test with single quote, sleep-based payloads, UNION SELECT. Try both string and integer injection.",
        "xss": "Test with <script>alert(1)</script>, event handlers, and SVG payloads. Check for reflection.",
        "lfi": "Try ../../etc/passwd, ..\\..\\windows\\system.ini, php://filter/convert.base64-encode/resource=.",
        "open_redirect": "Supply external URLs. Test with //evil.com, /\\evil.com, and URL-encoded variants.",
        "rce": "Test with command separators (;, |, &&, ||, `backticks`). Try sleep/ping for blind detection.",
        "info_leak": "Set parameter to true/1/yes. Look for debug output, stack traces, or internal paths.",
    }

    for item in result["details"]:
        param = item["param"]
        url_context = ""
        if " (" in param:
            parts = param.split(" (", 1)
            param = parts[0]
            url_context = parts[1].rstrip(")")

        for cls in item["classifications"]:
            suggestions.append({
                "param": param,
                "url_context": url_context,
                "vuln_class": cls["vuln_class"],
                "confidence": cls["confidence"],
                "test_suggestion": test_templates.get(cls["vuln_class"], "Manual review recommended."),
            })

    return suggestions
