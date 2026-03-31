"""
Notification module for BBRadar.

Sends scope change alerts, vuln lifecycle events, ingest summaries, and
program notifications to configured channels.  Currently supports:
  - Discord webhooks (per-event channel routing)
  - Desktop notifications (notify-send on Linux)

Security model — no PII by default:
  - ``verbosity`` (minimal / summary / verbose) controls how much detail is
    included in outbound messages.  Default is **minimal**.
  - Projects are identified by **ID only** (e.g. "Project #3"), never by
    name or program handle, unless ``verbose`` is explicitly enabled.
  - Vulnerability titles, endpoints, reproduction steps, request/response
    data, and target addresses are **never** included at any verbosity level.

Credentials are read from environment variables first, then config:
  BBRADAR_DISCORD_WEBHOOK        — default webhook (fallback for all events)
  BBRADAR_DISCORD_SCOPE_WEBHOOK  — scope change alerts
  BBRADAR_DISCORD_PROGRAMS_WEBHOOK — new program alerts
  BBRADAR_DISCORD_VULNS_WEBHOOK  — vulnerability lifecycle alerts
  BBRADAR_DISCORD_INGEST_WEBHOOK — ingest / scan result summaries
"""

import json
import os
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from ..core.config import load_config, set_config_value
from ..core.audit import log_action

# Discord embed limits
_EMBED_FIELD_VALUE_MAX = 1024
_EMBED_TITLE_MAX = 256
_EMBED_DESC_MAX = 4096
_MAX_EMBEDS = 10
_CONTENT_MAX = 2000


# ═══════════════════════════════════════════════════════════════════
# Credential / Config helpers
# ═══════════════════════════════════════════════════════════════════

VALID_VERBOSITY = ("minimal", "summary", "verbose")
VALID_EVENTS = ("scope", "programs", "vulns", "ingest")


def _get_verbosity() -> str:
    """Return the configured notification verbosity level."""
    env = os.environ.get("BBRADAR_NOTIFY_VERBOSITY", "").lower()
    if env in VALID_VERBOSITY:
        return env
    cfg = load_config()
    level = cfg.get("notifications", {}).get("verbosity", "minimal")
    return level if level in VALID_VERBOSITY else "minimal"


def _project_label(project_id: int, project_name: str | None = None) -> str:
    """Return a safe label for a project.

    • minimal / summary → ``"Project #<id>"``
    • verbose           → ``"Project #<id> (<name>)"`` if *name* provided
    """
    base = f"Project #{project_id}"
    if _get_verbosity() == "verbose" and project_name:
        return f"{base} ({project_name})"
    return base

def _get_discord_webhook(event: str | None = None) -> str | None:
    """Get Discord webhook URL from env var or config.

    If *event* is given ("scope" or "programs"), checks for an
    event-specific webhook first, then falls back to the default.
    """
    if event:
        env_key = f"BBRADAR_DISCORD_{event.upper()}_WEBHOOK"
        url = os.environ.get(env_key)
        if url:
            return url
        cfg = load_config()
        url = cfg.get("notifications", {}).get(f"discord_{event}_webhook")
        if url:
            return url
    # Fall back to default webhook
    url = os.environ.get("BBRADAR_DISCORD_WEBHOOK")
    if url:
        return url
    cfg = load_config()
    return cfg.get("notifications", {}).get("discord_webhook") or None


def _get_notify_config() -> dict:
    """Get notification preferences from config."""
    cfg = load_config()
    return cfg.get("notifications", {
        "discord_webhook": "",
        "desktop": False,
    })


def validate_webhook_url(url: str) -> str | None:
    """Validate a Discord webhook URL.  Returns error message or None."""
    if not url or not url.strip():
        return "Webhook URL cannot be empty"
    parsed = urlparse(url.strip())
    if parsed.scheme != "https":
        return "Webhook URL must use HTTPS"
    if not parsed.hostname or (parsed.hostname != "discord.com" and not parsed.hostname.endswith(".discord.com")):
        return "Webhook URL must be a discord.com URL"
    if not parsed.path.startswith("/api/webhooks/"):
        return "Webhook URL must start with /api/webhooks/"
    return None


def mask_webhook_url(url: str) -> str:
    """Mask a webhook URL for safe display: show first/last parts only."""
    if not url:
        return "(not set)"
    parts = url.rsplit("/", 1)
    if len(parts) == 2 and len(parts[1]) > 8:
        token = parts[1]
        return f"{parts[0]}/{token[:4]}...{token[-4:]}"
    return url[:40] + "..."


def configure_discord(webhook_url: str, event: str | None = None) -> str | None:
    """Save Discord webhook URL to config.

    *event* can be one of VALID_EVENTS for a channel-specific webhook,
    or None to set the default webhook.
    Returns error message if URL is invalid, None on success.
    """
    err = validate_webhook_url(webhook_url)
    if err:
        return err
    if event:
        set_config_value(f"notifications.discord_{event}_webhook", webhook_url)
    else:
        set_config_value("notifications.discord_webhook", webhook_url)
    return None


def configure_verbosity(level: str) -> str | None:
    """Set notification verbosity.  Returns error message or None."""
    level = level.lower()
    if level not in VALID_VERBOSITY:
        return f"Invalid verbosity '{level}'. Valid: {', '.join(VALID_VERBOSITY)}"
    set_config_value("notifications.verbosity", level)
    return None


def configure_desktop(enabled: bool = True):
    """Enable or disable desktop notifications."""
    set_config_value("notifications.desktop", enabled)


def get_status() -> dict:
    """Return status of all notification channels."""
    cfg = _get_notify_config()
    discord_url = _get_discord_webhook()
    scope_url = _get_discord_webhook("scope")
    programs_url = _get_discord_webhook("programs")
    vulns_url = _get_discord_webhook("vulns")
    ingest_url = _get_discord_webhook("ingest")

    def _channel_status(event_url, event_name):
        env_key = f"BBRADAR_DISCORD_{event_name.upper()}_WEBHOOK"
        return {
            "configured": bool(event_url),
            "source": "env" if os.environ.get(env_key) else "config",
            "uses_default": (event_url == discord_url
                             and not os.environ.get(env_key)
                             and not cfg.get(f"discord_{event_name}_webhook")),
        }

    return {
        "verbosity": _get_verbosity(),
        "discord": {
            "configured": bool(discord_url),
            "source": "env" if os.environ.get("BBRADAR_DISCORD_WEBHOOK") else "config",
        },
        "discord_scope": _channel_status(scope_url, "scope"),
        "discord_programs": _channel_status(programs_url, "programs"),
        "discord_vulns": _channel_status(vulns_url, "vulns"),
        "discord_ingest": _channel_status(ingest_url, "ingest"),
        "desktop": {
            "enabled": cfg.get("desktop", False),
        },
    }


# ═══════════════════════════════════════════════════════════════════
# Discord
# ═══════════════════════════════════════════════════════════════════

def _send_discord(content: str, embeds: list[dict] | None = None,
                  webhook_url: str | None = None,
                  _retries: int = 2) -> bool:
    """Send a message to a Discord webhook. Returns True on success.

    If *webhook_url* is not given, uses the default webhook.
    Retries on rate-limit (429) and transient server errors (5xx).
    """
    if not webhook_url:
        webhook_url = _get_discord_webhook()
    if not webhook_url:
        return False

    payload = {"username": "BBRadar"}
    if content:
        if len(content) > _CONTENT_MAX:
            payload["content"] = content[:_CONTENT_MAX - 20] + "\n_(truncated)_"
        else:
            payload["content"] = content
    if embeds:
        payload["embeds"] = _sanitize_embeds(embeds[:_MAX_EMBEDS])

    data = json.dumps(payload).encode("utf-8")
    req = Request(webhook_url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "BBRadar/0.5.2")

    for attempt in range(_retries + 1):
        try:
            with urlopen(req, timeout=15) as resp:
                return resp.status in (200, 204)
        except HTTPError as e:
            if e.code == 429 and attempt < _retries:
                # Rate limited — respect Retry-After header
                retry_after = float(e.headers.get("Retry-After", "2"))
                print(f"  ⏳ Discord rate-limited, retrying in {retry_after:.0f}s...",
                      file=sys.stderr, flush=True)
                time.sleep(min(retry_after, 10))
                continue
            if e.code >= 500 and attempt < _retries:
                time.sleep(1)
                continue
            # Log actionable error details for the user
            _log_discord_error(e)
            return False
        except (URLError, ValueError, OSError) as e:
            if attempt < _retries:
                time.sleep(1)
                continue
            print(f"  ✗ Discord webhook error: {e}", file=sys.stderr)
            return False
    return False


def _log_discord_error(e: HTTPError):
    """Print a helpful error for failed Discord webhook calls."""
    msgs = {
        400: "Bad request — payload may be too large or malformed",
        401: "Unauthorized — webhook token is invalid",
        403: "Forbidden — webhook may have been deleted or channel permissions changed",
        404: "Not found — webhook URL is invalid or has been deleted",
    }
    msg = msgs.get(e.code, f"HTTP {e.code}")
    print(f"  ✗ Discord webhook failed: {msg}", file=sys.stderr)
    try:
        body = e.read().decode("utf-8", errors="replace")[:200]
        if body:
            print(f"    Response: {body}", file=sys.stderr)
    except Exception:
        pass


def _sanitize_embeds(embeds: list[dict]) -> list[dict]:
    """Enforce Discord embed size limits to prevent API errors."""
    sanitized = []
    for embed in embeds:
        e = dict(embed)
        if e.get("title"):
            e["title"] = e["title"][:_EMBED_TITLE_MAX]
        if e.get("description"):
            desc = e["description"]
            if len(desc) > _EMBED_DESC_MAX:
                e["description"] = desc[:_EMBED_DESC_MAX - 20] + "\n_(truncated)_"
        if e.get("fields"):
            for field in e["fields"]:
                if len(field.get("value", "")) > _EMBED_FIELD_VALUE_MAX:
                    field["value"] = field["value"][:_EMBED_FIELD_VALUE_MAX - 20] + "\n_(truncated)_"
        sanitized.append(e)
    return sanitized


def _build_scope_change_embed(result: dict) -> dict:
    """Build a Discord embed for a single program's scope changes."""
    fields = []

    if result["new"]:
        lines = []
        for s in result["new"][:10]:
            bounty = " 💰" if s.get("eligible_for_bounty") else ""
            lines.append(f"`{s['asset_identifier']}` ({s['asset_type']}){bounty}")
        if len(result["new"]) > 10:
            lines.append(f"_...and {len(result['new']) - 10} more_")
        fields.append({
            "name": f"➕ New Assets ({len(result['new'])})",
            "value": "\n".join(lines),
            "inline": False,
        })

    if result["removed"]:
        lines = []
        for s in result["removed"][:10]:
            lines.append(f"`{s['asset_identifier']}` ({s['asset_type']})")
        if len(result["removed"]) > 10:
            lines.append(f"_...and {len(result['removed']) - 10} more_")
        fields.append({
            "name": f"➖ Removed Assets ({len(result['removed'])})",
            "value": "\n".join(lines),
            "inline": False,
        })

    if result["changed"]:
        lines = []
        for s in result["changed"][:10]:
            changes = ", ".join(
                f"{k}: {v['old']} → {v['new']}" for k, v in s["changes"].items()
            )
            lines.append(f"`{s['asset_identifier']}`: {changes}")
        if len(result["changed"]) > 10:
            lines.append(f"_...and {len(result['changed']) - 10} more_")
        fields.append({
            "name": f"🔄 Changed Assets ({len(result['changed'])})",
            "value": "\n".join(lines),
            "inline": False,
        })

    if result.get("auto_imported"):
        fields.append({
            "name": "⬇️ Auto-Imported",
            "value": f"{result['auto_imported']} new targets added to project [{result['project_id']}]",
            "inline": False,
        })

    h1_url = f"https://hackerone.com/{result['handle']}"

    return {
        "title": f"🔔 Scope Change: {result['handle']}",
        "description": f"[{result['name']}]({h1_url})",
        "color": 0xFF6B35,  # orange
        "fields": fields,
    }


def _build_new_programs_embed(programs: list[dict]) -> dict:
    """Build a Discord embed for newly discovered programs."""
    lines = []
    for p in programs[:15]:
        bounty = " 💰" if p.get("offers_bounties") else ""
        lines.append(f"[{p['handle']}](https://hackerone.com/{p['handle']}) — {p['name'][:40]}{bounty}")
    if len(programs) > 15:
        lines.append(f"_...and {len(programs) - 15} more_")

    return {
        "title": f"🆕 {len(programs)} New Programs Detected",
        "description": "\n".join(lines),
        "color": 0x00C853,  # green
    }


# ═══════════════════════════════════════════════════════════════════
# Desktop (notify-send)
# ═══════════════════════════════════════════════════════════════════

def _send_desktop(title: str, body: str) -> bool:
    """Send a desktop notification via notify-send. Returns True on success."""
    import subprocess
    try:
        subprocess.run(
            ["notify-send", "--app-name=BBRadar", "-i", "dialog-information", title, body],
            timeout=5,
            check=False,
            capture_output=True,
        )
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════
# High-level notification functions
# ═══════════════════════════════════════════════════════════════════

def notify_scope_changes(results: list[dict], db_path=None) -> dict:
    """
    Send notifications for scope change results.
    Only sends for programs that actually have changes.

    Returns {discord: bool, desktop: bool, programs_notified: int}
    """
    changed = [r for r in results if r.get("has_changes")]
    if not changed:
        return {"discord": False, "desktop": False, "programs_notified": 0}

    status = get_status()
    discord_ok = False
    desktop_ok = False

    # Discord — use scope-specific webhook
    if status["discord_scope"]["configured"]:
        embeds = [_build_scope_change_embed(r) for r in changed[:10]]
        total_new = sum(len(r.get("new", [])) for r in changed)
        total_removed = sum(len(r.get("removed", [])) for r in changed)
        total_changed_assets = sum(len(r.get("changed", [])) for r in changed)
        handles = ", ".join(r["handle"] for r in changed[:5])
        content = (f"🔔 **Scope changes** in {len(changed)} program(s): {handles}\n"
                   f"+{total_new} new, -{total_removed} removed, ~{total_changed_assets} changed")
        discord_ok = _send_discord(content, embeds=embeds,
                                   webhook_url=_get_discord_webhook("scope"))

    # Desktop
    if status["desktop"]["enabled"]:
        total_new = sum(len(r.get("new", [])) for r in changed)
        total_removed = sum(len(r.get("removed", [])) for r in changed)
        total_changed = sum(len(r.get("changed", [])) for r in changed)
        handles = ", ".join(r["handle"] for r in changed[:5])
        body = f"{total_new} new, {total_removed} removed, {total_changed} changed in: {handles}"
        desktop_ok = _send_desktop("BBRadar: Scope Changes", body)

    log_action("notifications_sent", "notifier", None, {
        "programs": len(changed),
        "discord": discord_ok,
        "desktop": desktop_ok,
    }, db_path)

    return {
        "discord": discord_ok,
        "desktop": desktop_ok,
        "programs_notified": len(changed),
    }


def notify_new_programs(programs: list[dict], db_path=None) -> dict:
    """
    Send notifications for newly discovered programs.

    Returns {discord: bool, desktop: bool, count: int}
    """
    if not programs:
        return {"discord": False, "desktop": False, "count": 0}

    status = get_status()
    discord_ok = False
    desktop_ok = False

    # Discord — use programs-specific webhook
    if status["discord_programs"]["configured"]:
        embed = _build_new_programs_embed(programs)
        handles = ", ".join(p["handle"] for p in programs[:10])
        more = f" (+{len(programs) - 10} more)" if len(programs) > 10 else ""
        content = f"🆕 **{len(programs)} new programs detected:** {handles}{more}"
        discord_ok = _send_discord(content, embeds=[embed],
                                   webhook_url=_get_discord_webhook("programs"))

    # Desktop
    if status["desktop"]["enabled"]:
        handles = ", ".join(p["handle"] for p in programs[:5])
        more = f" (+{len(programs) - 5} more)" if len(programs) > 5 else ""
        desktop_ok = _send_desktop(
            f"BBRadar: {len(programs)} New Programs",
            f"{handles}{more}",
        )

    log_action("new_programs_notified", "notifier", None, {
        "count": len(programs),
        "discord": discord_ok,
        "desktop": desktop_ok,
    }, db_path)

    return {
        "discord": discord_ok,
        "desktop": desktop_ok,
        "count": len(programs),
    }


def test_discord(event: str | None = None) -> bool:
    """Send a test message to verify Discord webhook is working.

    *event* can be "scope" or "programs" to test that specific channel.
    """
    url = _get_discord_webhook(event)
    label = f" ({event})" if event else ""
    return _send_discord(f"✅ **BBRadar connected!**{label} Alerts will appear here.",
                         webhook_url=url)


def test_desktop() -> bool:
    """Send a test desktop notification."""
    return _send_desktop("BBRadar", "Desktop notifications are working!")


# ═══════════════════════════════════════════════════════════════════
# Hacktivity notifications
# ═══════════════════════════════════════════════════════════════════

def _build_hacktivity_embed(result: dict) -> dict:
    """Build a Discord embed for newly disclosed hacktivity."""
    lines = []
    for r in result["new_reports"][:10]:
        sev = r.get("severity_rating", "?")
        bounty = f" — ${r['total_awarded_amount']:,.0f}" if r.get("total_awarded_amount") else ""
        cwe = f" [{r['cwe']}]" if r.get("cwe") else ""
        url = r.get("url", "")
        title_text = r["title"][:60]
        if url:
            title_text = f"[{title_text}]({url})"
        lines.append(f"**{sev}** {title_text}{cwe}{bounty}")
    if len(result["new_reports"]) > 10:
        lines.append(f"_...and {len(result['new_reports']) - 10} more_")

    h1_url = f"https://hackerone.com/{result['handle']}"

    return {
        "title": f"📄 New Disclosures: {result['handle']}",
        "description": f"[{result['name']}]({h1_url})\n\n" + "\n".join(lines),
        "color": 0x7B68EE,  # medium slate blue
    }


def notify_new_hacktivity(disclosures: list[dict], db_path=None) -> dict:
    """
    Send notifications for newly disclosed hacktivity items.

    Returns {discord: bool, desktop: bool, count: int}
    """
    if not disclosures:
        return {"discord": False, "desktop": False, "count": 0}

    status = get_status()
    discord_ok = False
    desktop_ok = False

    total_reports = sum(len(d["new_reports"]) for d in disclosures)

    # Discord — use scope webhook (hacktivity is program-specific intel)
    if status["discord_scope"]["configured"]:
        embeds = [_build_hacktivity_embed(d) for d in disclosures[:10]]
        handles = ", ".join(d["handle"] for d in disclosures[:5])
        content = f"📄 **{total_reports} new disclosed report(s)** in: {handles}"
        discord_ok = _send_discord(content, embeds=embeds,
                                   webhook_url=_get_discord_webhook("scope"))

    # Desktop
    if status["desktop"]["enabled"]:
        handles = ", ".join(d["handle"] for d in disclosures[:5])
        desktop_ok = _send_desktop(
            f"BBRadar: {total_reports} New Disclosures",
            f"New disclosed reports in: {handles}",
        )

    log_action("hacktivity_notified", "notifier", None, {
        "programs": len(disclosures),
        "reports": total_reports,
        "discord": discord_ok,
        "desktop": desktop_ok,
    }, db_path)

    return {
        "discord": discord_ok,
        "desktop": desktop_ok,
        "count": total_reports,
    }


# ═══════════════════════════════════════════════════════════════════
# KEV (actively exploited vulnerability) notifications
# ═══════════════════════════════════════════════════════════════════

def _build_kev_embed(entries: list[dict]) -> dict:
    """Build a Discord embed for new CISA KEV entries."""
    lines = []
    for e in entries[:15]:
        cve = e.get("cve_id", "?")
        vendor = e.get("vendor", "")
        product = e.get("product", "")
        name = e.get("name", "")[:50]
        added = e.get("date_added", "")
        lines.append(f"**{cve}** — {vendor} {product}: {name} (added {added})")
    if len(entries) > 15:
        lines.append(f"_...and {len(entries) - 15} more_")

    return {
        "title": f"⚠️ {len(entries)} New Actively Exploited Vulnerabilities",
        "description": "\n".join(lines),
        "color": 0xFF0000,  # red — critical security intelligence
        "footer": {"text": "Source: CISA Known Exploited Vulnerabilities catalog"},
    }


def notify_new_kev(entries: list[dict], db_path=None) -> dict:
    """
    Send notifications for newly added CISA KEV entries.

    *entries* should be a list of dicts with keys:
        cve_id, vendor, product, name, date_added

    Returns {discord: bool, desktop: bool, count: int}
    """
    if not entries:
        return {"discord": False, "desktop": False, "count": 0}

    status = get_status()
    discord_ok = False
    desktop_ok = False

    # Discord — use default webhook (KEV is global intel, not program-specific)
    if status["discord"]["configured"]:
        embed = _build_kev_embed(entries)
        cves = ", ".join(e["cve_id"] for e in entries[:5])
        more = f" (+{len(entries) - 5} more)" if len(entries) > 5 else ""
        content = f"⚠️ **{len(entries)} new actively exploited vuln(s) in CISA KEV:** {cves}{more}"
        discord_ok = _send_discord(content, embeds=[embed])

    # Desktop
    if status["desktop"]["enabled"]:
        cves = ", ".join(e["cve_id"] for e in entries[:3])
        more = f" (+{len(entries) - 3} more)" if len(entries) > 3 else ""
        desktop_ok = _send_desktop(
            f"BBRadar: {len(entries)} New KEV Entries",
            f"Actively exploited: {cves}{more}",
        )

    log_action("kev_notified", "notifier", None, {
        "count": len(entries),
        "discord": discord_ok,
        "desktop": desktop_ok,
    }, db_path)

    return {
        "discord": discord_ok,
        "desktop": desktop_ok,
        "count": len(entries),
    }


# ═══════════════════════════════════════════════════════════════════
# Vulnerability lifecycle notifications
# ═══════════════════════════════════════════════════════════════════

_SEV_COLOR = {
    "critical": 0xFF0000,
    "high": 0xFF6B35,
    "medium": 0xFFAA00,
    "low": 0x00AAFF,
    "informational": 0x888888,
}

_SEV_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "informational": "⚪",
}

# Only notify on these severities to avoid noise
_NOTIFY_SEVERITIES = {"critical", "high"}


def notify_vuln_created(vuln_id: int, project_id: int, severity: str,
                        project_name: str | None = None,
                        vuln_type: str | None = None,
                        db_path=None) -> dict:
    """
    Send notification when a critical/high vulnerability is created.

    Only fires for ``critical`` and ``high`` severity.  No finding titles,
    endpoints, or reproduction detail are ever included.

    Returns {discord: bool, desktop: bool}
    """
    severity = severity.lower()
    if severity not in _NOTIFY_SEVERITIES:
        return {"discord": False, "desktop": False}

    status = get_status()
    discord_ok = False
    desktop_ok = False
    label = _project_label(project_id, project_name)
    emoji = _SEV_EMOJI.get(severity, "⚪")
    verbosity = _get_verbosity()

    # Discord
    vulns_url = _get_discord_webhook("vulns")
    if vulns_url:
        desc = f"**Severity:** {severity.capitalize()}\n**Finding:** #{vuln_id}\n**Project:** {label}"
        if verbosity in ("summary", "verbose") and vuln_type:
            desc += f"\n**Type:** {vuln_type}"

        embed = {
            "title": f"{emoji} {severity.capitalize()} Finding Created",
            "description": desc,
            "color": _SEV_COLOR.get(severity, 0x888888),
        }
        content = f"{emoji} **{severity.capitalize()} finding** added to {label}"
        discord_ok = _send_discord(content, embeds=[embed], webhook_url=vulns_url)

    # Desktop
    if status["desktop"]["enabled"]:
        desktop_ok = _send_desktop(
            f"BBRadar: {severity.capitalize()} Finding",
            f"Finding #{vuln_id} added to {label}",
        )

    if discord_ok or desktop_ok:
        log_action("vuln_notified", "notifier", vuln_id, {
            "severity": severity,
            "project_id": project_id,
            "discord": discord_ok,
            "desktop": desktop_ok,
        }, db_path)

    return {"discord": discord_ok, "desktop": desktop_ok}


def notify_vuln_status_change(vuln_id: int, project_id: int,
                              old_status: str, new_status: str,
                              severity: str = "medium",
                              bounty_amount: float | None = None,
                              project_name: str | None = None,
                              db_path=None) -> dict:
    """
    Send notification when a vuln transitions to a notable state.

    Notable states: ``accepted``, ``rejected``, ``duplicate``.
    Also fires when ``bounty_amount`` is set.
    No finding titles or detail are included.
    """
    notable_states = {"accepted", "wontfix", "duplicate"}
    has_bounty = bounty_amount is not None and bounty_amount > 0
    if new_status not in notable_states and not has_bounty:
        return {"discord": False, "desktop": False}

    status = get_status()
    discord_ok = False
    desktop_ok = False
    label = _project_label(project_id, project_name)

    if has_bounty:
        emoji = "💰"
        title = "Bounty Awarded"
    elif new_status == "accepted":
        emoji = "✅"
        title = "Finding Accepted"
    elif new_status == "rejected":
        emoji = "❌"
        title = "Finding Rejected"
    elif new_status == "duplicate":
        emoji = "♻️"
        title = "Finding Duplicate"
    else:
        emoji = "🔄"
        title = f"Status: {new_status}"

    desc = (f"**Finding:** #{vuln_id}\n"
            f"**Severity:** {severity.capitalize()}\n"
            f"**Status:** {old_status} → {new_status}\n"
            f"**Project:** {label}")
    if has_bounty:
        desc += f"\n**Bounty:** ${bounty_amount:,.2f}"

    vulns_url = _get_discord_webhook("vulns")
    if vulns_url:
        embed = {
            "title": f"{emoji} {title}",
            "description": desc,
            "color": 0x00C853 if new_status == "accepted" or has_bounty else 0xFF6B35,
        }
        content = f"{emoji} **{title}** — finding #{vuln_id} in {label}"
        discord_ok = _send_discord(content, embeds=[embed], webhook_url=vulns_url)

    if status["desktop"]["enabled"]:
        desktop_ok = _send_desktop(
            f"BBRadar: {title}",
            f"Finding #{vuln_id} in {label}",
        )

    if discord_ok or desktop_ok:
        log_action("vuln_status_notified", "notifier", vuln_id, {
            "old_status": old_status,
            "new_status": new_status,
            "discord": discord_ok,
            "desktop": desktop_ok,
        }, db_path)

    return {"discord": discord_ok, "desktop": desktop_ok}


# ═══════════════════════════════════════════════════════════════════
# Ingest / scan result notifications
# ═══════════════════════════════════════════════════════════════════

def notify_ingest_complete(result: dict, project_id: int,
                           project_name: str | None = None,
                           db_path=None) -> dict:
    """
    Send notification after a scan ingest with new findings.

    Only fires when ``result["new"] > 0``.  No finding titles, endpoints,
    or target addresses are included.

    *result* is the dict returned by ``ingest_data()`` / ``ingest_file()``.

    Returns {discord: bool, desktop: bool}
    """
    new_count = result.get("new", 0)
    if new_count == 0:
        return {"discord": False, "desktop": False}

    status = get_status()
    discord_ok = False
    desktop_ok = False
    label = _project_label(project_id, project_name)
    verbosity = _get_verbosity()

    tool = result.get("tool", "unknown")
    dups = result.get("duplicates", 0)
    total = result.get("total_parsed", 0)

    # Count new findings by severity from created vulns
    by_sev = {}
    for f in result.get("findings", []):
        sev = f.get("severity", "informational")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    sev_line = ""
    if by_sev:
        parts = []
        for s in ("critical", "high", "medium", "low", "informational"):
            c = by_sev.get(s, 0)
            if c:
                parts.append(f"{_SEV_EMOJI.get(s, '•')} {c} {s}")
        sev_line = " — ".join(parts)

    # Discord
    ingest_url = _get_discord_webhook("ingest")
    if ingest_url:
        desc = f"**New findings:** {new_count}"
        if dups:
            desc += f"\n**Duplicates:** {dups}"
        if total:
            desc += f"\n**Total parsed:** {total}"
        desc += f"\n**Project:** {label}"
        if verbosity in ("summary", "verbose"):
            desc += f"\n**Tool:** {tool}"
        if sev_line:
            desc += f"\n\n{sev_line}"

        embed = {
            "title": f"📥 Scan Imported",
            "description": desc,
            "color": 0x00AAFF,
        }
        content = f"📥 **{new_count} new finding(s)** imported into {label}"
        discord_ok = _send_discord(content, embeds=[embed], webhook_url=ingest_url)

    # Desktop
    if status["desktop"]["enabled"]:
        desktop_ok = _send_desktop(
            f"BBRadar: {new_count} New Findings",
            f"Scan imported into {label}",
        )

    if discord_ok or desktop_ok:
        log_action("ingest_notified", "notifier", None, {
            "project_id": project_id,
            "tool": tool,
            "new": new_count,
            "discord": discord_ok,
            "desktop": desktop_ok,
        }, db_path)

    return {"discord": discord_ok, "desktop": desktop_ok}
