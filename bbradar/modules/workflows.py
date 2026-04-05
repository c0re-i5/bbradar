"""
Workflow engine.

Define and execute multi-step assessment playbooks. Workflows are YAML
files that describe sequential or parallel tool runs, with results
automatically ingested into the database.

Steps can be grouped for parallel execution using ``parallel: true``
on individual steps or by wrapping steps in a ``group`` block.
"""

import json
import shlex
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def _execute_step(step: dict, target_value: str, target_id: int,
                   dry_run: bool, db_path=None) -> dict:
    """Execute a single workflow step. Returns a result dict."""
    step_name = step.get("name", "unnamed")
    command_template = step.get("command", "")
    data_type = step.get("data_type", "other")
    source_tool = step.get("tool", "")
    timeout = step.get("timeout", 300)
    parser = step.get("parser", "lines")

    cmd_parts = shlex.split(command_template)
    cmd_args = [
        part.replace("{{target}}", target_value)
            .replace("{{domain}}", target_value)
        for part in cmd_parts
    ]

    lines = [f"  Command: {' '.join(cmd_args)}"]

    if dry_run:
        lines.append("  (dry run — skipped)")
        return {"ok": True, "lines": lines, "ingested": 0, "skipped": True}

    lines.append("  Running...")
    start = time.time()
    rc, stdout, stderr = run_tool(cmd_args, timeout=timeout)
    elapsed = time.time() - start
    lines.append(f"  Completed in {elapsed:.1f}s (exit code: {rc})")

    if rc != 0 and not stdout.strip():
        lines.append(f"  FAILED: {stderr[:200]}")
        return {"ok": False, "lines": lines, "ingested": 0, "required": step.get("required", False)}

    # Parse output
    if parser == "lines":
        values = [l.strip() for l in stdout.splitlines() if l.strip()]
    elif parser == "json":
        try:
            parsed_data = json.loads(stdout)
            if isinstance(parsed_data, list):
                values = [str(v) for v in parsed_data]
            elif isinstance(parsed_data, dict):
                values = [json.dumps(parsed_data)]
            else:
                values = [str(parsed_data)]
        except json.JSONDecodeError:
            values = [l.strip() for l in stdout.splitlines() if l.strip()]
    else:
        values = [l.strip() for l in stdout.splitlines() if l.strip()]

    ingested = 0
    if values:
        ingested = bulk_add_recon(target_id, data_type, values,
                                  source_tool=source_tool, db_path=db_path)
        lines.append(f"  Ingested {ingested} {data_type} entries")

    if step.get("save_raw", False):
        add_recon(target_id, "other", f"raw_{source_tool}_{target_value}",
                  source_tool=source_tool, raw_output=stdout, db_path=db_path)

    return {"ok": True, "lines": lines, "ingested": ingested}


def run_workflow(name: str, target_id: int, project_id: int = None,
                 dry_run: bool = False, db_path=None) -> dict:
    """
    Execute a workflow against a target.

    Steps with ``parallel: true`` that are adjacent are executed concurrently.
    Returns a dict with run status, output log, and counts.
    """
    wf = load_workflow(name)
    target = get_target(target_id, db_path)
    if not target:
        raise ValueError(f"Target #{target_id} not found")

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
    abort = False

    # Group adjacent parallel steps into batches
    steps = wf.get("steps", [])
    batches: list[list[tuple[int, dict]]] = []
    current_batch: list[tuple[int, dict]] = []
    for i, step in enumerate(steps):
        if step.get("parallel", False):
            current_batch.append((i, step))
        else:
            if current_batch:
                batches.append(current_batch)
                current_batch = []
            batches.append([(i, step)])
    if current_batch:
        batches.append(current_batch)

    total_steps = len(steps)
    for batch in batches:
        if abort:
            break

        if len(batch) == 1:
            # Sequential execution
            idx, step = batch[0]
            step_name = step.get("name", f"Step {idx + 1}")
            output_lines.append(f"\n[Step {idx + 1}/{total_steps}] {step_name}")
            res = _execute_step(step, target_value, target_id, dry_run, db_path)
            output_lines.extend(res["lines"])
            results["steps_run"] += 1
            results["data_ingested"] += res["ingested"]
            if res["ok"]:
                results["steps_ok"] += 1
            else:
                results["steps_failed"] += 1
                if res.get("required"):
                    output_lines.append("  (required step failed — aborting workflow)")
                    abort = True
        else:
            # Parallel execution
            names = ", ".join(s.get("name", f"Step {i + 1}") for i, s in batch)
            output_lines.append(f"\n[Parallel] {names}")
            max_workers = min(len(batch), wf.get("max_parallel", 4))
            futures = {}
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                for idx, step in batch:
                    fut = executor.submit(
                        _execute_step, step, target_value, target_id, dry_run, db_path
                    )
                    futures[fut] = (idx, step)
                for fut in as_completed(futures):
                    idx, step = futures[fut]
                    step_name = step.get("name", f"Step {idx + 1}")
                    output_lines.append(f"\n  [{step_name}]")
                    res = fut.result()
                    output_lines.extend(f"  {l}" for l in res["lines"])
                    results["steps_run"] += 1
                    results["data_ingested"] += res["ingested"]
                    if res["ok"]:
                        results["steps_ok"] += 1
                    else:
                        results["steps_failed"] += 1
                        if res.get("required"):
                            output_lines.append("  (required step failed — aborting after batch)")
                            abort = True

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
