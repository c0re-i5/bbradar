"""
Notification module for BBRadar.

Sends scope change alerts and new program notifications to configured
channels. Currently supports:
  - Discord webhooks
  - Desktop notifications (notify-send on Linux)

Credentials are read from environment variables first, then config:
  BBRADAR_DISCORD_WEBHOOK — Discord webhook URL
"""

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..core.config import load_config, set_config_value
from ..core.audit import log_action


# ═══════════════════════════════════════════════════════════════════
# Credential / Config helpers
# ═══════════════════════════════════════════════════════════════════

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


def configure_discord(webhook_url: str, event: str | None = None):
    """Save Discord webhook URL to config.

    *event* can be "scope" or "programs" for a channel-specific webhook,
    or None to set the default webhook.
    """
    if event:
        set_config_value(f"notifications.discord_{event}_webhook", webhook_url)
    else:
        set_config_value("notifications.discord_webhook", webhook_url)


def configure_desktop(enabled: bool = True):
    """Enable or disable desktop notifications."""
    set_config_value("notifications.desktop", enabled)


def get_status() -> dict:
    """Return status of all notification channels."""
    cfg = _get_notify_config()
    discord_url = _get_discord_webhook()
    scope_url = _get_discord_webhook("scope")
    programs_url = _get_discord_webhook("programs")
    return {
        "discord": {
            "configured": bool(discord_url),
            "source": "env" if os.environ.get("BBRADAR_DISCORD_WEBHOOK") else "config",
        },
        "discord_scope": {
            "configured": bool(scope_url),
            "source": "env" if os.environ.get("BBRADAR_DISCORD_SCOPE_WEBHOOK") else "config",
            "uses_default": scope_url == discord_url and not os.environ.get("BBRADAR_DISCORD_SCOPE_WEBHOOK")
                            and not cfg.get("discord_scope_webhook"),
        },
        "discord_programs": {
            "configured": bool(programs_url),
            "source": "env" if os.environ.get("BBRADAR_DISCORD_PROGRAMS_WEBHOOK") else "config",
            "uses_default": programs_url == discord_url and not os.environ.get("BBRADAR_DISCORD_PROGRAMS_WEBHOOK")
                            and not cfg.get("discord_programs_webhook"),
        },
        "desktop": {
            "enabled": cfg.get("desktop", False),
        },
    }


# ═══════════════════════════════════════════════════════════════════
# Discord
# ═══════════════════════════════════════════════════════════════════

def _send_discord(content: str, embeds: list[dict] | None = None,
                  webhook_url: str | None = None) -> bool:
    """Send a message to a Discord webhook. Returns True on success.

    If *webhook_url* is not given, uses the default webhook.
    """
    if not webhook_url:
        webhook_url = _get_discord_webhook()
    if not webhook_url:
        return False

    payload = {"username": "BBRadar"}
    if content:
        payload["content"] = content[:2000]
    if embeds:
        payload["embeds"] = embeds[:10]

    data = json.dumps(payload).encode("utf-8")
    req = Request(webhook_url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "BBRadar/0.3.1")

    try:
        with urlopen(req, timeout=15) as resp:
            return resp.status in (200, 204)
    except (HTTPError, URLError, ValueError, OSError):
        return False


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
        discord_ok = _send_discord("", embeds=embeds,
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
        discord_ok = _send_discord("", embeds=[embed],
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
        discord_ok = _send_discord("", embeds=embeds,
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
