"""
Tests for the notification module.

Tests notification logic, message formatting, and channel dispatch
using mocked HTTP calls and subprocess calls.
"""

from unittest.mock import patch, MagicMock, call
from urllib.error import HTTPError
import json

import pytest

from bbradar.modules import notifier


# ═══════════════════════════════════════════════════════════════════
# Test data builders
# ═══════════════════════════════════════════════════════════════════

def _scope_result(handle="testprog", has_changes=True, new=None, removed=None, changed=None):
    """Build a mock check_program result."""
    return {
        "handle": handle,
        "name": f"Test {handle}",
        "new": new or [],
        "removed": removed or [],
        "changed": changed or [],
        "has_changes": has_changes,
        "auto_imported": 0,
        "project_id": None,
    }


def _new_asset(identifier="new.example.com", asset_type="domain", bounty=True):
    return {
        "asset_identifier": identifier,
        "asset_type": asset_type,
        "eligible_for_bounty": bounty,
        "eligible_for_submission": True,
        "max_severity": "critical",
        "instruction": "",
    }


def _changed_asset(identifier="changed.example.com"):
    return {
        "asset_identifier": identifier,
        "asset_type": "domain",
        "eligible_for_bounty": True,
        "eligible_for_submission": True,
        "max_severity": "critical",
        "instruction": "",
        "changes": {"eligible_for_bounty": {"old": False, "new": True}},
    }


# ═══════════════════════════════════════════════════════════════════
# Tests: Configuration
# ═══════════════════════════════════════════════════════════════════

class TestConfiguration:
    @patch.dict("os.environ", {"BBRADAR_DISCORD_WEBHOOK": "https://discord.com/api/webhooks/test/abc"})
    def test_env_var_takes_priority(self):
        url = notifier._get_discord_webhook()
        assert url == "https://discord.com/api/webhooks/test/abc"

    @patch.dict("os.environ", {}, clear=True)
    @patch("bbradar.modules.notifier.load_config",
           return_value={"notifications": {"discord_webhook": "https://discord.com/api/webhooks/cfg/xyz"}})
    def test_config_fallback(self, mock_cfg):
        # Remove env var if present
        import os
        os.environ.pop("BBRADAR_DISCORD_WEBHOOK", None)
        url = notifier._get_discord_webhook()
        assert url == "https://discord.com/api/webhooks/cfg/xyz"

    @patch.dict("os.environ", {}, clear=True)
    @patch("bbradar.modules.notifier.load_config", return_value={})
    def test_no_config_returns_none(self, mock_cfg):
        import os
        os.environ.pop("BBRADAR_DISCORD_WEBHOOK", None)
        url = notifier._get_discord_webhook()
        assert url is None

    @patch("bbradar.modules.notifier.set_config_value")
    def test_configure_discord(self, mock_set):
        notifier.configure_discord("https://discord.com/api/webhooks/new/url")
        mock_set.assert_called_once_with(
            "notifications.discord_webhook",
            "https://discord.com/api/webhooks/new/url",
        )

    @patch("bbradar.modules.notifier.set_config_value")
    def test_configure_discord_scope(self, mock_set):
        notifier.configure_discord("https://discord.com/api/webhooks/scope/url", event="scope")
        mock_set.assert_called_once_with(
            "notifications.discord_scope_webhook",
            "https://discord.com/api/webhooks/scope/url",
        )

    @patch("bbradar.modules.notifier.set_config_value")
    def test_configure_discord_programs(self, mock_set):
        notifier.configure_discord("https://discord.com/api/webhooks/progs/url", event="programs")
        mock_set.assert_called_once_with(
            "notifications.discord_programs_webhook",
            "https://discord.com/api/webhooks/progs/url",
        )

    @patch("bbradar.modules.notifier.set_config_value")
    def test_configure_desktop(self, mock_set):
        notifier.configure_desktop(True)
        mock_set.assert_called_once_with("notifications.desktop", True)


class TestGetStatus:
    @patch.dict("os.environ", {"BBRADAR_DISCORD_WEBHOOK": "https://discord.com/api/webhooks/test/ok"})
    @patch("bbradar.modules.notifier.load_config", return_value={})
    @patch("bbradar.modules.notifier._get_notify_config",
           return_value={"desktop": True})
    def test_all_configured(self, mock_cfg, mock_load):
        status = notifier.get_status()
        assert status["discord"]["configured"] is True
        assert status["discord"]["source"] == "env"
        assert status["discord_scope"]["configured"] is True
        assert status["discord_scope"]["uses_default"] is True
        assert status["discord_programs"]["configured"] is True
        assert status["discord_programs"]["uses_default"] is True
        assert status["desktop"]["enabled"] is True


# ═══════════════════════════════════════════════════════════════════
# Tests: Discord message building
# ═══════════════════════════════════════════════════════════════════

class TestDiscordEmbeds:
    def test_scope_change_embed_has_new_assets(self):
        result = _scope_result(
            has_changes=True,
            new=[_new_asset("a.example.com"), _new_asset("b.example.com")],
        )
        embed = notifier._build_scope_change_embed(result)
        assert "Scope Change" in embed["title"]
        assert "testprog" in embed["title"]
        assert len(embed["fields"]) == 1
        assert "New Assets" in embed["fields"][0]["name"]
        assert "a.example.com" in embed["fields"][0]["value"]

    def test_scope_change_embed_all_change_types(self):
        result = _scope_result(
            has_changes=True,
            new=[_new_asset()],
            removed=[_new_asset("gone.example.com")],
            changed=[_changed_asset()],
        )
        embed = notifier._build_scope_change_embed(result)
        assert len(embed["fields"]) == 3

    def test_new_programs_embed(self):
        programs = [
            {"handle": "newco", "name": "New Corp", "offers_bounties": True},
            {"handle": "startup", "name": "Startup Inc", "offers_bounties": False},
        ]
        embed = notifier._build_new_programs_embed(programs)
        assert "2 New Programs" in embed["title"]
        assert "newco" in embed["description"]


# ═══════════════════════════════════════════════════════════════════
# Tests: Discord sending
# ═══════════════════════════════════════════════════════════════════

class TestDiscordSend:
    @patch("bbradar.modules.notifier._get_discord_webhook", return_value=None)
    def test_no_webhook_returns_false(self, _):
        assert notifier._send_discord("test") is False

    @patch("bbradar.modules.notifier.urlopen")
    @patch("bbradar.modules.notifier._get_discord_webhook",
           return_value="https://discord.com/api/webhooks/test/ok")
    def test_successful_send(self, _, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 204
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        assert notifier._send_discord("test message") is True

        # Verify the request payload
        req_call = mock_urlopen.call_args
        req_obj = req_call[0][0]
        payload = json.loads(req_obj.data)
        assert payload["username"] == "BBRadar"
        assert payload["content"] == "test message"


# ═══════════════════════════════════════════════════════════════════
# Tests: Desktop notification
# ═══════════════════════════════════════════════════════════════════

class TestDesktopNotification:
    @patch("subprocess.run")
    def test_send_desktop_calls_notify_send(self, mock_run):
        result = notifier._send_desktop("Title", "Body text")
        assert result is True
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "notify-send"
        assert "Title" in args
        assert "Body text" in args

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_missing_notify_send(self, _):
        result = notifier._send_desktop("Title", "Body")
        assert result is False


# ═══════════════════════════════════════════════════════════════════
# Tests: High-level notification dispatch
# ═══════════════════════════════════════════════════════════════════

class TestNotifyDispatch:
    @patch("bbradar.modules.notifier.log_action")
    @patch("bbradar.modules.notifier._send_desktop", return_value=True)
    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier.get_status", return_value={
        "discord": {"configured": True, "source": "env"},
        "discord_scope": {"configured": True, "source": "env", "uses_default": True},
        "discord_programs": {"configured": True, "source": "env", "uses_default": True},
        "desktop": {"enabled": True},
    })
    def test_scope_changes_notified(self, _, mock_discord, mock_desktop, mock_log):
        results = [
            _scope_result(has_changes=True, new=[_new_asset()]),
            _scope_result(handle="noop", has_changes=False),
        ]
        out = notifier.notify_scope_changes(results)
        assert out["discord"] is True
        assert out["desktop"] is True
        assert out["programs_notified"] == 1

    @patch("bbradar.modules.notifier.log_action")
    @patch("bbradar.modules.notifier._send_discord", return_value=False)
    @patch("bbradar.modules.notifier.get_status", return_value={
        "discord": {"configured": False, "source": "config"},
        "discord_scope": {"configured": False, "source": "config", "uses_default": False},
        "discord_programs": {"configured": False, "source": "config", "uses_default": False},
        "desktop": {"enabled": False},
    })
    def test_no_channels_configured(self, _, mock_discord, mock_log):
        results = [_scope_result(has_changes=True, new=[_new_asset()])]
        out = notifier.notify_scope_changes(results)
        assert out["discord"] is False
        assert out["desktop"] is False

    def test_no_changes_skips_notifications(self):
        results = [_scope_result(has_changes=False)]
        out = notifier.notify_scope_changes(results)
        assert out["programs_notified"] == 0

    @patch("bbradar.modules.notifier.log_action")
    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier.get_status", return_value={
        "discord": {"configured": True, "source": "env"},
        "discord_scope": {"configured": True, "source": "env", "uses_default": True},
        "discord_programs": {"configured": True, "source": "env", "uses_default": True},
        "desktop": {"enabled": False},
    })
    def test_new_programs_notified(self, _, mock_discord, mock_log):
        programs = [
            {"handle": "newco", "name": "New Corp", "offers_bounties": True},
        ]
        out = notifier.notify_new_programs(programs)
        assert out["discord"] is True
        assert out["count"] == 1

    def test_empty_programs_skips(self):
        out = notifier.notify_new_programs([])
        assert out["count"] == 0


# ═══════════════════════════════════════════════════════════════════
# Tests: Webhook URL validation
# ═══════════════════════════════════════════════════════════════════

class TestWebhookValidation:
    def test_valid_url(self):
        assert notifier.validate_webhook_url(
            "https://discord.com/api/webhooks/12345/abcdef"
        ) is None

    def test_empty_url(self):
        assert notifier.validate_webhook_url("") is not None

    def test_http_rejected(self):
        err = notifier.validate_webhook_url("http://discord.com/api/webhooks/12345/abc")
        assert "HTTPS" in err

    def test_non_discord_host(self):
        err = notifier.validate_webhook_url("https://evil.com/api/webhooks/12345/abc")
        assert "discord.com" in err

    def test_wrong_path(self):
        err = notifier.validate_webhook_url("https://discord.com/not-webhooks/12345/abc")
        assert "webhooks" in err.lower()


class TestMaskWebhookUrl:
    def test_masks_token(self):
        url = "https://discord.com/api/webhooks/12345/abcdefghijklmnop"
        masked = notifier.mask_webhook_url(url)
        assert "abcdefghijklmnop" not in masked
        assert "abcd" in masked
        assert "mnop" in masked

    def test_empty_url(self):
        assert "not set" in notifier.mask_webhook_url("")

    def test_none_url(self):
        assert "not set" in notifier.mask_webhook_url(None)


# ═══════════════════════════════════════════════════════════════════
# Tests: Embed sanitization
# ═══════════════════════════════════════════════════════════════════

class TestSanitizeEmbeds:
    def test_truncates_long_field_value(self):
        embed = {
            "title": "Test",
            "fields": [{"name": "Big", "value": "x" * 2000, "inline": False}],
        }
        result = notifier._sanitize_embeds([embed])
        assert len(result[0]["fields"][0]["value"]) <= notifier._EMBED_FIELD_VALUE_MAX

    def test_truncates_long_description(self):
        embed = {"title": "T", "description": "d" * 5000}
        result = notifier._sanitize_embeds([embed])
        assert len(result[0]["description"]) <= notifier._EMBED_DESC_MAX

    def test_truncates_long_title(self):
        embed = {"title": "T" * 300}
        result = notifier._sanitize_embeds([embed])
        assert len(result[0]["title"]) <= notifier._EMBED_TITLE_MAX

    def test_short_embed_unchanged(self):
        embed = {"title": "OK", "description": "Fine", "fields": []}
        result = notifier._sanitize_embeds([embed])
        assert result[0] == embed


# ═══════════════════════════════════════════════════════════════════
# Tests: Rate limit handling
# ═══════════════════════════════════════════════════════════════════

class TestRateLimitRetry:
    @patch("bbradar.modules.notifier.time.sleep")
    @patch("bbradar.modules.notifier.urlopen")
    @patch("bbradar.modules.notifier._get_discord_webhook",
           return_value="https://discord.com/api/webhooks/test/ok")
    def test_retries_on_429(self, _, mock_urlopen, mock_sleep):
        # First call: 429, second call: success
        err_response = MagicMock()
        err_response.code = 429
        err_response.headers = {"Retry-After": "1"}
        err_response.read.return_value = b""
        rate_err = HTTPError("url", 429, "Rate Limited", err_response.headers, None)

        ok_response = MagicMock()
        ok_response.status = 204
        ok_response.__enter__ = MagicMock(return_value=ok_response)
        ok_response.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [rate_err, ok_response]
        assert notifier._send_discord("test") is True
        mock_sleep.assert_called_once()

    @patch("bbradar.modules.notifier.urlopen")
    @patch("bbradar.modules.notifier._get_discord_webhook",
           return_value="https://discord.com/api/webhooks/test/ok")
    def test_returns_false_on_persistent_error(self, _, mock_urlopen):
        err = HTTPError("url", 403, "Forbidden", {}, None)
        err.read = MagicMock(return_value=b"forbidden")
        mock_urlopen.side_effect = err
        assert notifier._send_discord("test") is False


class TestConfigureDiscordValidation:
    @patch("bbradar.modules.notifier.set_config_value")
    def test_valid_url_saved(self, mock_set):
        result = notifier.configure_discord("https://discord.com/api/webhooks/123/abc")
        assert result is None
        mock_set.assert_called_once()

    def test_invalid_url_rejected(self):
        result = notifier.configure_discord("http://evil.com/steal")
        assert result is not None
        assert isinstance(result, str)


# ═══════════════════════════════════════════════════════════════════
# Tests: Verbosity and project labels
# ═══════════════════════════════════════════════════════════════════

class TestVerbosity:
    @patch.dict("os.environ", {"BBRADAR_NOTIFY_VERBOSITY": "summary"})
    def test_env_var_overrides(self):
        assert notifier._get_verbosity() == "summary"

    @patch.dict("os.environ", {"BBRADAR_NOTIFY_VERBOSITY": "INVALID"})
    @patch("bbradar.modules.notifier.load_config", return_value={})
    def test_invalid_env_falls_back_to_config(self, _):
        assert notifier._get_verbosity() == "minimal"

    @patch.dict("os.environ", {}, clear=True)
    @patch("bbradar.modules.notifier.load_config",
           return_value={"notifications": {"verbosity": "verbose"}})
    def test_config_value(self, _):
        import os
        os.environ.pop("BBRADAR_NOTIFY_VERBOSITY", None)
        assert notifier._get_verbosity() == "verbose"

    @patch("bbradar.modules.notifier.set_config_value")
    def test_configure_valid(self, mock_set):
        assert notifier.configure_verbosity("summary") is None
        mock_set.assert_called_once_with("notifications.verbosity", "summary")

    def test_configure_invalid(self):
        err = notifier.configure_verbosity("debug")
        assert err is not None
        assert "Invalid" in err


class TestProjectLabel:
    @patch("bbradar.modules.notifier._get_verbosity", return_value="minimal")
    def test_minimal_hides_name(self, _):
        assert notifier._project_label(3, "secret-program") == "Project #3"

    @patch("bbradar.modules.notifier._get_verbosity", return_value="summary")
    def test_summary_hides_name(self, _):
        assert notifier._project_label(3, "secret-program") == "Project #3"

    @patch("bbradar.modules.notifier._get_verbosity", return_value="verbose")
    def test_verbose_shows_name(self, _):
        assert notifier._project_label(3, "secret-program") == "Project #3 (secret-program)"

    @patch("bbradar.modules.notifier._get_verbosity", return_value="verbose")
    def test_verbose_no_name(self, _):
        assert notifier._project_label(3) == "Project #3"


# ═══════════════════════════════════════════════════════════════════
# Tests: Vuln notifications
# ═══════════════════════════════════════════════════════════════════

_VULNS_WH = "https://discord.com/api/webhooks/vulns/test"


class TestNotifyVulnCreated:
    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier._get_discord_webhook",
           side_effect=lambda e=None: _VULNS_WH if e == "vulns" else None)
    @patch("bbradar.modules.notifier.get_status",
           return_value={"desktop": {"enabled": False}})
    @patch("bbradar.modules.notifier.log_action")
    def test_fires_for_critical(self, mock_log, _, __, mock_send):
        result = notifier.notify_vuln_created(1, 5, "critical")
        assert result["discord"] is True
        mock_send.assert_called_once()
        payload_content = mock_send.call_args[0][0]
        assert "Project #5" in payload_content
        assert "Critical" in payload_content or "critical" in payload_content.lower()

    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier._get_discord_webhook",
           side_effect=lambda e=None: _VULNS_WH if e == "vulns" else None)
    @patch("bbradar.modules.notifier.get_status",
           return_value={"desktop": {"enabled": False}})
    @patch("bbradar.modules.notifier.log_action")
    def test_fires_for_high(self, mock_log, _, __, mock_send):
        result = notifier.notify_vuln_created(2, 3, "high")
        assert result["discord"] is True

    def test_skips_medium(self):
        result = notifier.notify_vuln_created(1, 1, "medium")
        assert result == {"discord": False, "desktop": False}

    def test_skips_low(self):
        result = notifier.notify_vuln_created(1, 1, "low")
        assert result == {"discord": False, "desktop": False}

    def test_skips_informational(self):
        result = notifier.notify_vuln_created(1, 1, "informational")
        assert result == {"discord": False, "desktop": False}

    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier._get_discord_webhook",
           side_effect=lambda e=None: _VULNS_WH if e == "vulns" else None)
    @patch("bbradar.modules.notifier.get_status",
           return_value={"desktop": {"enabled": False}})
    @patch("bbradar.modules.notifier.log_action")
    @patch("bbradar.modules.notifier._get_verbosity", return_value="minimal")
    def test_no_name_in_minimal(self, _, mock_log, __, ___, mock_send):
        notifier.notify_vuln_created(1, 5, "critical", project_name="secret")
        content = mock_send.call_args[0][0]
        assert "secret" not in content
        embed_desc = mock_send.call_args[1]["embeds"][0]["description"]
        assert "secret" not in embed_desc


class TestNotifyVulnStatusChange:
    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier._get_discord_webhook",
           side_effect=lambda e=None: _VULNS_WH if e == "vulns" else None)
    @patch("bbradar.modules.notifier.get_status",
           return_value={"desktop": {"enabled": False}})
    @patch("bbradar.modules.notifier.log_action")
    def test_fires_on_accepted(self, mock_log, _, __, mock_send):
        result = notifier.notify_vuln_status_change(1, 3, "new", "accepted")
        assert result["discord"] is True

    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier._get_discord_webhook",
           side_effect=lambda e=None: _VULNS_WH if e == "vulns" else None)
    @patch("bbradar.modules.notifier.get_status",
           return_value={"desktop": {"enabled": False}})
    @patch("bbradar.modules.notifier.log_action")
    def test_fires_on_rejected(self, mock_log, _, __, mock_send):
        result = notifier.notify_vuln_status_change(1, 3, "new", "wontfix")
        assert result["discord"] is True

    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier._get_discord_webhook",
           side_effect=lambda e=None: _VULNS_WH if e == "vulns" else None)
    @patch("bbradar.modules.notifier.get_status",
           return_value={"desktop": {"enabled": False}})
    @patch("bbradar.modules.notifier.log_action")
    def test_fires_on_bounty(self, mock_log, _, __, mock_send):
        result = notifier.notify_vuln_status_change(
            1, 3, "accepted", "accepted", bounty_amount=500.0)
        assert result["discord"] is True
        embed_desc = mock_send.call_args[1]["embeds"][0]["description"]
        assert "$500.00" in embed_desc

    def test_skips_non_notable_status(self):
        result = notifier.notify_vuln_status_change(1, 3, "new", "triaged")
        assert result == {"discord": False, "desktop": False}

    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier._get_discord_webhook",
           side_effect=lambda e=None: _VULNS_WH if e == "vulns" else None)
    @patch("bbradar.modules.notifier.get_status",
           return_value={"desktop": {"enabled": False}})
    @patch("bbradar.modules.notifier.log_action")
    def test_fires_on_duplicate(self, mock_log, _, __, mock_send):
        result = notifier.notify_vuln_status_change(1, 3, "new", "duplicate")
        assert result["discord"] is True


# ═══════════════════════════════════════════════════════════════════
# Tests: Ingest notifications
# ═══════════════════════════════════════════════════════════════════

_INGEST_WH = "https://discord.com/api/webhooks/ingest/test"


class TestNotifyIngestComplete:
    def _result(self, new=3, dups=2, total=10, tool="nuclei", findings=None):
        if findings is None:
            findings = [{"severity": "high"}] * new
        return {
            "tool": tool,
            "file": "scan.json",
            "total_parsed": total,
            "new": new,
            "duplicates": dups,
            "out_of_scope": 0,
            "skipped": 0,
            "created_ids": list(range(1, new + 1)),
            "create_errors": [],
            "findings": findings,
        }

    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier._get_discord_webhook",
           side_effect=lambda e=None: _INGEST_WH if e == "ingest" else None)
    @patch("bbradar.modules.notifier.get_status",
           return_value={"desktop": {"enabled": False}})
    @patch("bbradar.modules.notifier.log_action")
    def test_fires_with_new_findings(self, mock_log, _, __, mock_send):
        result = notifier.notify_ingest_complete(self._result(), 5)
        assert result["discord"] is True
        content = mock_send.call_args[0][0]
        assert "3 new finding" in content
        assert "Project #5" in content

    def test_skips_when_no_new(self):
        result = notifier.notify_ingest_complete(self._result(new=0, findings=[]), 5)
        assert result == {"discord": False, "desktop": False}

    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier._get_discord_webhook",
           side_effect=lambda e=None: _INGEST_WH if e == "ingest" else None)
    @patch("bbradar.modules.notifier.get_status",
           return_value={"desktop": {"enabled": False}})
    @patch("bbradar.modules.notifier.log_action")
    @patch("bbradar.modules.notifier._get_verbosity", return_value="summary")
    def test_summary_includes_tool(self, _, mock_log, __, ___, mock_send):
        notifier.notify_ingest_complete(self._result(tool="nmap"), 1)
        embed_desc = mock_send.call_args[1]["embeds"][0]["description"]
        assert "nmap" in embed_desc

    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier._get_discord_webhook",
           side_effect=lambda e=None: _INGEST_WH if e == "ingest" else None)
    @patch("bbradar.modules.notifier.get_status",
           return_value={"desktop": {"enabled": False}})
    @patch("bbradar.modules.notifier.log_action")
    @patch("bbradar.modules.notifier._get_verbosity", return_value="minimal")
    def test_minimal_hides_tool(self, _, mock_log, __, ___, mock_send):
        notifier.notify_ingest_complete(self._result(tool="nmap"), 1)
        embed_desc = mock_send.call_args[1]["embeds"][0]["description"]
        assert "nmap" not in embed_desc

    @patch("bbradar.modules.notifier._send_discord", return_value=True)
    @patch("bbradar.modules.notifier._get_discord_webhook",
           side_effect=lambda e=None: _INGEST_WH if e == "ingest" else None)
    @patch("bbradar.modules.notifier.get_status",
           return_value={"desktop": {"enabled": False}})
    @patch("bbradar.modules.notifier.log_action")
    def test_severity_breakdown(self, mock_log, _, __, mock_send):
        findings = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
        ]
        notifier.notify_ingest_complete(
            self._result(new=3, findings=findings), 1)
        embed_desc = mock_send.call_args[1]["embeds"][0]["description"]
        assert "2 critical" in embed_desc
        assert "1 high" in embed_desc


# ═══════════════════════════════════════════════════════════════════
# Tests: get_status includes new channels
# ═══════════════════════════════════════════════════════════════════

class TestGetStatusNewChannels:
    @patch("bbradar.modules.notifier._get_notify_config", return_value={})
    @patch("bbradar.modules.notifier._get_discord_webhook", return_value=None)
    @patch("bbradar.modules.notifier._get_verbosity", return_value="minimal")
    def test_includes_vulns_and_ingest(self, _, __, ___):
        status = notifier.get_status()
        assert "discord_vulns" in status
        assert "discord_ingest" in status
        assert "verbosity" in status
        assert status["verbosity"] == "minimal"
