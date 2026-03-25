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

def _get_discord_webhook() -> str | None:
    """Get Discord webhook URL from env var or config."""
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


def configure_discord(webhook_url: str):
    """Save Discord webhook URL to config."""
    set_config_value("notifications.discord_webhook", webhook_url)


def configure_desktop(enabled: bool = True):
    """Enable or disable desktop notifications."""
    set_config_value("notifications.desktop", enabled)


def get_status() -> dict:
    """Return status of all notification channels."""
    cfg = _get_notify_config()
    discord_url = _get_discord_webhook()
    return {
        "discord": {
            "configured": bool(discord_url),
            "source": "env" if os.environ.get("BBRADAR_DISCORD_WEBHOOK") else "config",
        },
        "desktop": {
            "enabled": cfg.get("desktop", False),
        },
    }


# ═══════════════════════════════════════════════════════════════════
# Discord
# ═══════════════════════════════════════════════════════════════════

def _send_discord(content: str, embeds: list[dict] | None = None) -> bool:
    """Send a message to the configured Discord webhook. Returns True on success."""
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

    try:
        with urlopen(req, timeout=15) as resp:
            return resp.status in (200, 204)
    except (HTTPError, URLError, OSError):
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

    # Discord
    if status["discord"]["configured"]:
        embeds = [_build_scope_change_embed(r) for r in changed[:10]]
        discord_ok = _send_discord("", embeds=embeds)

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

    # Discord
    if status["discord"]["configured"]:
        embed = _build_new_programs_embed(programs)
        discord_ok = _send_discord("", embeds=[embed])

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


def test_discord() -> bool:
    """Send a test message to verify Discord webhook is working."""
    return _send_discord("✅ **BBRadar connected!** Scope change alerts will appear here.")


def test_desktop() -> bool:
    """Send a test desktop notification."""
    return _send_desktop("BBRadar", "Desktop notifications are working!")
