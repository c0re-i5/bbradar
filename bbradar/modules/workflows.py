"""
Workflow engine.

Define and execute multi-step assessment playbooks. Workflows are YAML
files that describe sequential or parallel tool runs, with results
automatically ingested into the database.
"""

import json
import shlex
import sys
import time
from datetime import datetime
from pathlib import Path

import yaml

from ..core.database import get_connection
from ..core.audit import log_action
from ..core.config import load_config
from ..core.utils import run_tool
from .recon import bulk_add_recon, add_recon
from .targets import get_target


WORKFLOW_DIR = Path(__file__).parent.parent / "workflows"


def list_workflows() -> list[dict]:
    """List available workflow definitions."""
    workflows = []
    for wf_dir in (WORKFLOW_DIR,):
        if not wf_dir.exists():
            continue
        for f in sorted(wf_dir.glob("*.yaml")):
            try:
                with open(f) as fh:
                    data = yaml.safe_load(fh)
                workflows.append({
                    "name": data.get("name", f.stem),
                    "description": data.get("description", ""),
                    "file": str(f),
                    "steps": len(data.get("steps", [])),
                })
            except Exception as e:
                print(f"  warning: could not load workflow {f.name}: {e}", file=sys.stderr)
    return workflows


def load_workflow(name: str) -> dict:
    """Load a workflow definition by name."""
    # Search built-in workflows
    for wf_dir in (WORKFLOW_DIR,):
        path = wf_dir / f"{name}.yaml"
        if path.exists():
            with open(path) as f:
                return yaml.safe_load(f)
    # Try as a relative path within the workflow directory only
    path = Path(name)
    if path.is_absolute():
        # Validate it lives inside the workflow directory
        try:
            path.resolve().relative_to(WORKFLOW_DIR.resolve())
        except ValueError:
            raise FileNotFoundError(
                f"Workflow not found: {name} (absolute paths must be inside {WORKFLOW_DIR})"
            )
    if path.exists():
        resolved = path.resolve()
        try:
            resolved.relative_to(WORKFLOW_DIR.resolve())
        except ValueError:
            raise FileNotFoundError(f"Workflow not found: {name}")
        with open(resolved) as f:
            return yaml.safe_load(f)
    raise FileNotFoundError(f"Workflow not found: {name}")


def preflight_check(name: str) -> dict:
    """
    Check that all tools required by a workflow are installed and available.
    Returns {ok: bool, steps: [{name, tool, command, available, path}], missing: [str]}.
    """
    import shutil
    wf = load_workflow(name)
    steps_info = []
    missing = []
    for step in wf.get("steps", []):
        tool_name = step.get("tool", "")
        command_tmpl = step.get("command", "")
        # Extract the binary name (first word of command)
        binary = command_tmpl.split()[0] if command_tmpl else tool_name
        binary_path = shutil.which(binary)
        available = binary_path is not None
        if not available:
            missing.append(binary)
        steps_info.append({
            "name": step.get("name", ""),
            "tool": tool_name,
            "binary": binary,
            "available": available,
            "path": binary_path or "",
            "required": step.get("required", False),
        })
    return {
        "ok": len(missing) == 0,
        "steps": steps_info,
        "missing": sorted(set(missing)),
    }


def run_workflow(name: str, target_id: int, project_id: int = None,
                 dry_run: bool = False, db_path=None) -> dict:
    """
    Execute a workflow against a target.

    Returns a dict with run status, output log, and counts.
    """
    wf = load_workflow(name)
    target = get_target(target_id, db_path)
    if not target:
        raise ValueError(f"Target #{target_id} not found")

    # Pre-flight check
    check = preflight_check(name)
    if not check["ok"] and not dry_run:
        required_missing = [
            s["binary"] for s in check["steps"]
            if not s["available"] and s["required"]
        ]
        if required_missing:
            raise RuntimeError(
                f"Missing required tools: {', '.join(required_missing)}. "
                f"Install them before running this workflow."
            )

    target_value = target["value"]
    project_id = project_id or target["project_id"]

    # Create workflow run record
    run_id = None
    if not dry_run:
        with get_connection(db_path) as conn:
            cursor = conn.execute(
                """INSERT INTO workflow_runs (workflow_name, project_id, target_id, status)
                   VALUES (?, ?, ?, 'running')""",
                (name, project_id, target_id),
            )
            run_id = cursor.lastrowid

    output_lines = []
    results = {"steps_run": 0, "steps_ok": 0, "steps_failed": 0, "data_ingested": 0}

    steps = wf.get("steps", [])

    for i, step in enumerate(steps, 1):
        step_name = step.get("name", f"Step {i}")
        command_template = step.get("command", "")
        data_type = step.get("data_type", "other")
        source_tool = step.get("tool", "")
        timeout = step.get("timeout", 300)
        parser = step.get("parser", "lines")  # lines | json | nmap_grep

        # Substitute variables in command — build as list to prevent injection
        cmd_parts = shlex.split(command_template)
        cmd_args = []
        for part in cmd_parts:
            cmd_args.append(
                part.replace("{{target}}", target_value)
                    .replace("{{domain}}", target_value)
            )

        output_lines.append(f"\n[Step {i}/{len(steps)}] {step_name}")
        output_lines.append(f"  Command: {' '.join(cmd_args)}")

        if dry_run:
            output_lines.append("  (dry run — skipped)")
            results["steps_run"] += 1
            continue

        output_lines.append(f"  Running...")
        start = time.time()
        rc, stdout, stderr = run_tool(cmd_args, timeout=timeout)
        elapsed = time.time() - start
        output_lines.append(f"  Completed in {elapsed:.1f}s (exit code: {rc})")

        results["steps_run"] += 1

        if rc != 0 and not stdout.strip():
            output_lines.append(f"  FAILED: {stderr[:200]}")
            results["steps_failed"] += 1
            if step.get("required", False):
                output_lines.append("  (required step failed — aborting workflow)")
                break
            continue

        results["steps_ok"] += 1

        # Parse and ingest data
        if parser == "lines":
            values = [l.strip() for l in stdout.splitlines() if l.strip()]
        elif parser == "json":
            try:
                parsed = json.loads(stdout)
                if isinstance(parsed, list):
                    values = [str(v) for v in parsed]
                elif isinstance(parsed, dict):
                    values = [json.dumps(parsed)]
                else:
                    values = [str(parsed)]
            except json.JSONDecodeError:
                values = [l.strip() for l in stdout.splitlines() if l.strip()]
        else:
            values = [l.strip() for l in stdout.splitlines() if l.strip()]

        if values:
            count = bulk_add_recon(target_id, data_type, values,
                                   source_tool=source_tool, db_path=db_path)
            results["data_ingested"] += count
            output_lines.append(f"  Ingested {count} {data_type} entries")

        # Store raw output as a note if requested
        if step.get("save_raw", False):
            add_recon(target_id, "other", f"raw_{source_tool}_{target_value}",
                      source_tool=source_tool, raw_output=stdout, db_path=db_path)

    # Finalize
    output_log = "\n".join(output_lines)

    if not dry_run and run_id:
        status = "completed" if results["steps_failed"] == 0 else "failed"
        with get_connection(db_path) as conn:
            conn.execute(
                """UPDATE workflow_runs SET status = ?, finished_at = datetime('now'),
                   output_log = ? WHERE id = ?""",
                (status, output_log, run_id),
            )
        log_action("ran_workflow", "workflow", run_id,
                   {"name": name, "target": target_value, **results}, db_path)

    results["run_id"] = run_id
    results["output"] = output_log
    return results


def get_workflow_run(run_id: int, db_path=None) -> dict | None:
    """Get details of a workflow run."""
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM workflow_runs WHERE id = ?", (run_id,)
        ).fetchone()
    return dict(row) if row else None


def list_workflow_runs(project_id: int = None, target_id: int = None,
                       limit: int = 20, db_path=None) -> list[dict]:
    """List workflow run history."""
    with get_connection(db_path) as conn:
        query = "SELECT * FROM workflow_runs WHERE 1=1"
        params: list = []
        if project_id is not None:
            query += " AND project_id = ?"
            params.append(project_id)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]
