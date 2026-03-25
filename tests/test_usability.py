"""
Tests for usability features: active project, --json, --stdin, --no-color, completion.
"""

import json
import os
import subprocess
import sys
import pytest

from bbradar.core.config import (
    get_active_project, set_active_project, clear_active_project, _ACTIVE_PROJECT_FILE,
)
from bbradar.core.utils import severity_color, set_no_color, _no_color
from bbradar.modules.projects import create_project, get_project
from bbradar.modules.targets import list_targets


# ═══════════════════════════════════════════════════════════════════
# Active project context
# ═══════════════════════════════════════════════════════════════════

class TestActiveProject:
    def test_set_and_get(self, tmp_path, monkeypatch):
        active_file = tmp_path / ".active_project"
        monkeypatch.setattr("bbradar.core.config._ACTIVE_PROJECT_FILE", active_file)
        set_active_project(42)
        assert get_active_project() == 42

    def test_get_returns_none_when_unset(self, tmp_path, monkeypatch):
        active_file = tmp_path / ".active_project"
        monkeypatch.setattr("bbradar.core.config._ACTIVE_PROJECT_FILE", active_file)
        assert get_active_project() is None

    def test_clear(self, tmp_path, monkeypatch):
        active_file = tmp_path / ".active_project"
        monkeypatch.setattr("bbradar.core.config._ACTIVE_PROJECT_FILE", active_file)
        set_active_project(7)
        clear_active_project()
        assert get_active_project() is None

    def test_invalid_file_content(self, tmp_path, monkeypatch):
        active_file = tmp_path / ".active_project"
        active_file.write_text("not-a-number")
        monkeypatch.setattr("bbradar.core.config._ACTIVE_PROJECT_FILE", active_file)
        assert get_active_project() is None

    def test_set_none_removes_file(self, tmp_path, monkeypatch):
        active_file = tmp_path / ".active_project"
        monkeypatch.setattr("bbradar.core.config._ACTIVE_PROJECT_FILE", active_file)
        set_active_project(5)
        assert active_file.exists()
        set_active_project(None)
        assert not active_file.exists()


# ═══════════════════════════════════════════════════════════════════
# NO_COLOR / --no-color
# ═══════════════════════════════════════════════════════════════════

class TestNoColor:
    def test_severity_color_default_has_ansi(self):
        set_no_color(False)
        result = severity_color("high")
        assert "\033[" in result
        assert "high" in result

    def test_severity_color_no_color_flag(self):
        set_no_color(True)
        result = severity_color("high")
        assert result == "high"
        assert "\033[" not in result
        set_no_color(False)  # reset

    def test_severity_color_no_color_env(self, monkeypatch):
        set_no_color(False)
        monkeypatch.setenv("NO_COLOR", "1")
        result = severity_color("critical")
        assert result == "critical"
        assert "\033[" not in result


# ═══════════════════════════════════════════════════════════════════
# _resolve_project_id
# ═══════════════════════════════════════════════════════════════════

class TestResolveProjectId:
    def test_explicit_id_wins(self, tmp_path, monkeypatch):
        from bbradar.cli import _resolve_project_id
        active_file = tmp_path / ".active_project"
        monkeypatch.setattr("bbradar.core.config._ACTIVE_PROJECT_FILE", active_file)
        set_active_project(99)

        class FakeArgs:
            project_id = 5

        assert _resolve_project_id(FakeArgs()) == 5

    def test_falls_back_to_active(self, tmp_path, monkeypatch):
        from bbradar.cli import _resolve_project_id
        active_file = tmp_path / ".active_project"
        monkeypatch.setattr("bbradar.core.config._ACTIVE_PROJECT_FILE", active_file)
        set_active_project(12)

        class FakeArgs:
            project_id = None

        assert _resolve_project_id(FakeArgs()) == 12

    def test_exits_when_no_context(self, tmp_path, monkeypatch):
        from bbradar.cli import _resolve_project_id
        active_file = tmp_path / ".active_project"
        monkeypatch.setattr("bbradar.core.config._ACTIVE_PROJECT_FILE", active_file)
        clear_active_project()

        class FakeArgs:
            project_id = None

        with pytest.raises(SystemExit):
            _resolve_project_id(FakeArgs())


# ═══════════════════════════════════════════════════════════════════
# _json_out
# ═══════════════════════════════════════════════════════════════════

class TestJsonOut:
    def test_json_output_true(self, capsys):
        from bbradar.cli import _json_out

        class FakeArgs:
            json_output = True

        data = [{"id": 1, "name": "test"}]
        assert _json_out(FakeArgs(), data) is True
        output = capsys.readouterr().out
        parsed = json.loads(output)
        assert parsed[0]["name"] == "test"

    def test_json_output_false(self, capsys):
        from bbradar.cli import _json_out

        class FakeArgs:
            json_output = False

        assert _json_out(FakeArgs(), {"x": 1}) is False
        assert capsys.readouterr().out == ""


# ═══════════════════════════════════════════════════════════════════
# Shell completion
# ═══════════════════════════════════════════════════════════════════

class TestCompletion:
    def test_bash_completion(self, capsys):
        from bbradar.cli import cmd_completion

        class FakeArgs:
            shell = "bash"

        cmd_completion(FakeArgs())
        output = capsys.readouterr().out
        assert "complete -F _bb_completions bb" in output
        assert "COMPREPLY" in output

    def test_zsh_completion(self, capsys):
        from bbradar.cli import cmd_completion

        class FakeArgs:
            shell = "zsh"

        cmd_completion(FakeArgs())
        output = capsys.readouterr().out
        assert "compdef _bb bb" in output

    def test_fish_completion(self, capsys):
        from bbradar.cli import cmd_completion

        class FakeArgs:
            shell = "fish"

        cmd_completion(FakeArgs())
        output = capsys.readouterr().out
        assert "complete -c bb" in output


# ═══════════════════════════════════════════════════════════════════
# Stdin piping (target add --stdin)
# ═══════════════════════════════════════════════════════════════════

class TestStdinPiping:
    def test_target_add_stdin(self, tmp_db, monkeypatch):
        """Simulate stdin piping for target add."""
        from io import StringIO
        pid = create_project("StdinTest", db_path=tmp_db)

        # Mock stdin
        fake_stdin = StringIO("example.com\ntest.com\n# comment\n\nbad.com\n")
        monkeypatch.setattr("sys.stdin", fake_stdin)

        from bbradar.modules.targets import add_target
        count = 0
        for line in fake_stdin:
            val = line.strip()
            if val and not val.startswith("#"):
                add_target(pid, "domain", val, db_path=tmp_db)
                count += 1

        assert count == 3
        tgts = list_targets(pid, db_path=tmp_db)
        values = [t["value"] for t in tgts]
        assert "example.com" in values
        assert "test.com" in values
        assert "bad.com" in values

    def test_recon_add_stdin(self, tmp_db):
        """Simulate stdin piping for recon add via bulk_add_recon."""
        from bbradar.modules.recon import bulk_add_recon, list_recon
        from bbradar.modules.targets import add_target
        pid = create_project("ReconStdin", db_path=tmp_db)
        tid = add_target(pid, "domain", "example.com", db_path=tmp_db)

        values = ["sub1.example.com", "sub2.example.com", "sub3.example.com"]
        count = bulk_add_recon(tid, "subdomain", values, source_tool="stdin", db_path=tmp_db)
        assert count == 3

        data = list_recon(target_id=tid, db_path=tmp_db)
        recon_values = [d["value"] for d in data]
        assert "sub1.example.com" in recon_values
