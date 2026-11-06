"""Workflow runs always reach a terminal status."""

from unittest.mock import patch

import pytest

from bbradar.modules.projects import create_project, update_project
from bbradar.modules.targets import add_target
from bbradar.modules.recon import list_recon
from bbradar.modules.workflows import run_workflow, get_workflow_run


def _execute(db, steps, tool_side_effect):
    pid = create_project("Workflow", db_path=db)
    tid = add_target(pid, "domain", "example.com", db_path=db)
    wf = {"name": "t", "steps": steps, "max_parallel": 4}
    with patch("bbradar.modules.workflows.load_workflow", return_value=wf), \
         patch("bbradar.modules.workflows.preflight_check",
               return_value={"ok": True, "steps": [], "missing": []}), \
         patch("bbradar.modules.workflows.run_tool", side_effect=tool_side_effect):
        result = run_workflow("t", tid, db_path=db)
    return pid, tid, result


class TestWorkflowTerminalStatus:
    def test_success_is_completed(self, tmp_db):
        steps = [{"name": "echo", "command": "echo {{target}}", "tool": "echo", "data_type": "url"}]
        _, _, result = _execute(tmp_db, steps, [(0, "https://example.com/\n", "")])
        assert result["status"] == "completed"
        run = get_workflow_run(result["run_id"], tmp_db)
        assert run["status"] == "completed"
        assert run["finished_at"]

    def test_optional_failure_is_completed_with_errors(self, tmp_db):
        steps = [{"name": "echo", "command": "echo {{target}}", "tool": "echo",
                  "data_type": "url", "required": False}]
        _, tid, result = _execute(
            tmp_db, steps, [(1, "https://partial.example/\n", "warn")],
        )
        assert result["status"] == "completed_with_errors"
        assert result["steps_failed"] == 1
        assert get_workflow_run(result["run_id"], tmp_db)["status"] == "completed_with_errors"
        values = [r["value"] for r in list_recon(target_id=tid, db_path=tmp_db)]
        assert "https://partial.example/" in values

    def test_nonzero_without_stdout_is_failed_step(self, tmp_db):
        steps = [{"name": "echo", "command": "echo {{target}}", "tool": "echo"}]
        _, _, result = _execute(tmp_db, steps, [(2, "  \n", "nope")])
        assert result["status"] == "completed_with_errors"
        assert result["steps_failed"] == 1
        assert result["data_ingested"] == 0

    def test_required_failure_skips_the_rest_and_fails(self, tmp_db):
        steps = [
            {"name": "first", "command": "echo a", "tool": "echo", "required": True},
            {"name": "second", "command": "echo b", "tool": "echo"},
        ]
        calls = []

        def _tool(*_args, **_kwargs):
            calls.append(1)
            return (1, "", "boom")

        _, _, result = _execute(tmp_db, steps, _tool)
        assert result["status"] == "failed"
        assert result["steps_skipped"] == 1
        assert len(calls) == 1
        assert "(skipped)" in result["output"]
        run = get_workflow_run(result["run_id"], tmp_db)
        assert run["status"] == "failed"
        assert "(skipped)" in run["output_log"]

    def test_bad_template_does_not_stick_at_running(self, tmp_db):
        steps = [{"name": "bad", "command": 'echo "unterminated', "tool": "echo"}]
        _, _, result = _execute(tmp_db, steps, [(0, "", "")])
        assert result["status"] == "completed_with_errors"
        assert "invalid command template" in result["output"]
        assert get_workflow_run(result["run_id"], tmp_db)["status"] != "running"

    def test_keyboard_interrupt_cancels(self, tmp_db):
        steps = [
            {"name": "first", "command": "echo a", "tool": "echo"},
            {"name": "second", "command": "echo b", "tool": "echo"},
        ]
        pid = create_project("Workflow", db_path=tmp_db)
        tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
        wf = {"name": "t", "steps": steps}
        with patch("bbradar.modules.workflows.load_workflow", return_value=wf), \
             patch("bbradar.modules.workflows.preflight_check",
                   return_value={"ok": True, "steps": [], "missing": []}), \
             patch("bbradar.modules.workflows.run_tool", side_effect=KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt):
                run_workflow("t", tid, db_path=tmp_db)
        from bbradar.modules.workflows import list_workflow_runs
        runs = list_workflow_runs(target_id=tid, db_path=tmp_db)
        assert len(runs) == 1
        assert runs[0]["status"] == "cancelled"
        assert runs[0]["finished_at"]
        assert "(skipped)" in (runs[0]["output_log"] or "")

    def test_parallel_step_exception_is_finalized(self, tmp_db):
        steps = [
            {"name": "a", "command": "echo a", "tool": "echo", "parallel": True},
            {"name": "b", "command": "echo b", "tool": "echo", "parallel": True},
        ]
        with patch("bbradar.modules.workflows._execute_step", side_effect=RuntimeError("pool")):
            pid = create_project("Workflow", db_path=tmp_db)
            tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
            wf = {"name": "t", "steps": steps}
            with patch("bbradar.modules.workflows.load_workflow", return_value=wf), \
                 patch("bbradar.modules.workflows.preflight_check",
                       return_value={"ok": True, "steps": [], "missing": []}):
                result = run_workflow("t", tid, db_path=tmp_db)
        assert result["status"] == "completed_with_errors"
        assert result["steps_failed"] == 2
        assert get_workflow_run(result["run_id"], tmp_db)["status"] == "completed_with_errors"

    def test_paused_project_refuses_a_real_run(self, tmp_db):
        pid = create_project("Workflow", db_path=tmp_db)
        tid = add_target(pid, "domain", "example.com", db_path=tmp_db)
        update_project(pid, status="paused", db_path=tmp_db)
        wf = {"name": "t", "steps": [{"name": "echo", "command": "echo x", "tool": "echo"}]}
        with patch("bbradar.modules.workflows.load_workflow", return_value=wf), \
             patch("bbradar.modules.workflows.preflight_check",
                   return_value={"ok": True, "steps": [], "missing": []}):
            with pytest.raises(ValueError, match="paused"):
                run_workflow("t", tid, db_path=tmp_db)
        from bbradar.modules.workflows import list_workflow_runs
        assert list_workflow_runs(target_id=tid, db_path=tmp_db) == []
