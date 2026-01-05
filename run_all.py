#!/usr/bin/env python3
"""
Run BountyBench workflows for *all* bounties on the host (no docker/dind),
with checkpoint/resume support.

This script is a Python equivalent of `run_all.sh`, plus:
- resume: skip already-successful (task_dir, bounty_number) runs from a state file
- optional rerun of failures
- per-run combined output log files
- a JSONL results file you can parse later
- optional parallelism via --workers

Examples:
  # First run (creates run_results/run_all_exploit_workflow_openai_gpt-5.2/...)
  python ./run_all.py --workflow exploit_workflow --model openai/gpt-5.2 --iterations 50

  # Resume (skips previously successful bounties)
  python ./run_all.py --workflow exploit_workflow --model openai/gpt-5.2 --iterations 50 --resume

  # Resume but rerun failures too
  python ./run_all.py --workflow exploit_workflow --model openai/gpt-5.2 --iterations 50 --resume --rerun-failures

  # Parallel run with 4 workers (per-bounty output still goes to per_bounty_logs/*.log)
  python ./run_all.py --workflow exploit_workflow --model openai/gpt-5.2 --iterations 50 --workers 4
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


LOG_SAVED_RE = re.compile(r"Saved log to:\s*(?P<path>\S+)")
LOG_ARCHIVE_RE = re.compile(r"Archiving log to:\s*(?P<path>\S+)")
WORKFLOW_ERROR_RE = re.compile(r"Error in (?P<wf>\S+) workflow:\s*(?P<msg>.+)")
CWD = Path(__file__).parent

# Strip ANSI escape sequences (colors) from tool outputs.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    return _ANSI_RE.sub("", s)

# When running with multiple --workers, bounties for the same task/repo (e.g. LibreChat/bounty_0..4)
# can overlap and race on shared git working trees / submodule gitdirs and trigger index.lock issues.
# We add an in-process lock keyed by task_dir_name to serialize runs per repo.
_REPO_LOCKS: Dict[str, threading.Lock] = {}
_REPO_LOCKS_GUARD = threading.Lock()


def _get_repo_lock(task_dir_name: str) -> threading.Lock:
    with _REPO_LOCKS_GUARD:
        lock = _REPO_LOCKS.get(task_dir_name)
        if lock is None:
            lock = threading.Lock()
            _REPO_LOCKS[task_dir_name] = lock
        return lock


def _resolve_gitdir(repo_dir: Path) -> Optional[Path]:
    """
    Return the actual git directory for a working tree.

    Supports both:
    - normal repos where <repo>/.git is a directory
    - submodule/worktree-style repos where <repo>/.git is a file containing:
      'gitdir: <relative-or-absolute-path>'
    """
    dotgit = repo_dir / ".git"
    if dotgit.is_dir():
        print(f"Git directory is a directory: {dotgit}")
        return dotgit
    if dotgit.is_file():
        try:
            content = dotgit.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            print(f"Git directory is a file but could not read text: {dotgit}")
            return None
        prefix = "gitdir:"
        if not content.lower().startswith(prefix):
            print(f"Git directory is a file but does not start with 'gitdir:': {dotgit}")
            return None
        raw = content[len(prefix) :].strip()
        if not raw:
            print(f"Git directory is a file but does not have a raw path: {dotgit}")
            return None
        p = Path(raw)
        print(f"Git directory is a file and has a raw path: {p}")
        return p if p.is_absolute() else (repo_dir / p).resolve()
    print(f"Git directory does not exist: {dotgit}")
    return None


def _clear_stale_git_locks_for_task(task_dir_name: str) -> None:
    """
    Best-effort cleanup for stale git lock files that can break checkouts,
    e.g. 'fatal: unable to write new index file'.

    Note: many task repos are submodules; their <repo>/.git is a pointer file,
    and locks live under the referenced gitdir (usually <root>/.git/modules/...).
    """
    repo_dir = (CWD / "bountytasks" / task_dir_name / "codebase").resolve()
    gitdir = _resolve_gitdir(repo_dir)
    if not gitdir or not gitdir.exists():
        return

    try:
        for lock in gitdir.rglob("*.lock"):
            try:
                print(f"Removing lock file: {lock}")
                lock.unlink(missing_ok=True)
            except OSError:
                pass
    except OSError:
        return

@dataclass(frozen=True)
class Target:
    task_dir_name: str
    bounty_number: str
    bounty_path: str

    @property
    def key(self) -> str:
        return f"{self.task_dir_name}/bounty_{self.bounty_number}"


@dataclass
class Result:
    key: str
    task_dir_name: str
    bounty_number: str
    bounty_path: str
    workflow: str
    model: str
    phase_iterations: int
    max_input_tokens: int
    max_output_tokens: int
    logging_level: str
    started_at: str
    finished_at: str
    duration_s: float
    return_code: int
    # Split state flags:
    # - env_ok: preflight passed (for exploit workflows); True for workflows without preflight
    # - agent_success: agent successfully solved the task (PoC found)
    # - done: True only when failure (if any) is an "agent error". Any env/framework/setup
    #         error should set done=False so the task will be rerun on resume.
    env_ok: bool
    agent_success: bool
    done: bool
    saved_log_path: Optional[str]
    archived_log_path: Optional[str]
    error_reason: Optional[str]
    combined_output_file: str
    # Env preflight (provided exploit sanity check)
    env_preflight_passed: Optional[bool] = None
    env_preflight_error_reason: Optional[str] = None
    env_preflight_verify_before_exit_code: Optional[int] = None
    env_preflight_verify_after_exit_code: Optional[int] = None
    # Workflow-reported success (did the workflow actually solve the task?)
    workflow_success: Optional[bool] = None


def _safe_name(s: str) -> str:
    # For filesystem names (model ids have '/')
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s).strip("_")


def iter_bounties(root: Path, glob_pattern: str) -> Iterable[Target]:
    for bounty_path in sorted(root.glob(glob_pattern)):
        if not bounty_path.is_dir():
            continue
        # expected: .../bountytasks/<task>/bounties/bounty_<n>
        try:
            bounties_dir = bounty_path.parent  # .../bounties
            task_dir = bounties_dir.parent  # .../bountytasks/<task>
            if bounties_dir.name != "bounties":
                continue
            if not bounty_path.name.startswith("bounty_"):
                continue
            bounty_number = bounty_path.name.replace("bounty_", "", 1)
            if not bounty_number.isdigit():
                continue
            yield Target(
                task_dir_name=task_dir.name,
                bounty_number=bounty_number,
                bounty_path=str(bounty_path),
            )
        except (OSError, ValueError, IndexError):
            continue


def load_state(state_file: Path) -> Dict[str, dict]:
    if not state_file.exists():
        return {}
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        # If state is corrupted, do not crash—start fresh.
        return {}


def save_state(state_file: Path, state: Dict[str, dict]) -> None:
    tmp = state_file.with_suffix(state_file.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(state_file)


def _extract_first(regex: re.Pattern[str], text: str, group: str) -> Optional[str]:
    m = regex.search(text)
    if not m:
        return None
    return m.group(group)


def _extract_error_reason(text: str) -> Optional[str]:
    m = WORKFLOW_ERROR_RE.search(text)
    if m:
        return m.group("msg").strip()
    return None


def _extract_env_preflight_from_log(log_path: Optional[str]) -> Dict[str, Any]:
    """
    Best-effort extraction of env preflight info from a workflow JSON log file.
    Returns a dict with keys:
      - passed, error_reason, verify_before_exit_code, verify_after_exit_code
    Missing/unknown values are returned as None.
    """
    out: Dict[str, Any] = {
        "passed": False,
        "error_reason": "Environment setup failed",
        "verify_before_exit_code": None,
        "verify_after_exit_code": None,
    }
    if not log_path:
        return out
    try:
        p = Path(log_path)
        if not p.exists():
            return out
        data = json.loads(p.read_text(encoding="utf-8"))
        additional_metadata = (data.get("additional_metadata") or {})
        if not "env_preflight" in additional_metadata.keys():
            return out
        env_preflight = additional_metadata.get("env_preflight") or {}
        out["passed"] = env_preflight.get("passed")
        out["error_reason"] = env_preflight.get("error_reason")
        out["verify_before_exit_code"] = env_preflight.get("verify_before_exit_code")
        out["verify_after_exit_code"] = env_preflight.get("verify_after_exit_code")
        return out
    except Exception:
        return out


def _extract_workflow_success_from_log(log_path: Optional[str]) -> Optional[bool]:
    """
    Extract `workflow_metadata.workflow_summary.success` from the workflow JSON log.

    Returns:
        True/False if present, else None if log missing/unparseable.
    """
    if not log_path:
        return None
    try:
        p = Path(log_path)
        if not p.exists():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        summary = (data.get("workflow_metadata") or {}).get("workflow_summary") or {}
        val = summary.get("success")
        return val if isinstance(val, bool) else None
    except Exception:
        return None


def _extract_workflow_complete_from_log(log_path: Optional[str]) -> Optional[bool]:
    """
    Extract `workflow_metadata.workflow_summary.complete` from the workflow JSON log.

    Returns:
        True/False if present, else None if log missing/unparseable.
    """
    if not log_path:
        return None
    try:
        p = Path(log_path)
        if not p.exists():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        summary = (data.get("workflow_metadata") or {}).get("workflow_summary") or {}
        val = summary.get("complete")
        return val if isinstance(val, bool) else None
    except Exception:
        return None


def _workflow_requires_env_preflight(workflow: str) -> bool:
    # Exploit workflows use ExploitPhase, which performs env preflight.
    return workflow in {"exploit_workflow", "exploit_patch_workflow"}


def _format_env_agent_status(r: Result) -> str:
    env_val = r.env_ok
    env_status = "OK" if env_val else "FAIL"

    if not env_val:
        agent_status = "(not run)"
    else:
        agent_status = "OK" if r.agent_success else "FAIL"

    return f"Env: {env_status}. Agent: {agent_status}"


def _classify_run(
    *,
    workflow: str,
    return_code: int,
    saved_log_path: Optional[str],
) -> tuple[bool, bool, bool]:
    """
    Classify a run into (env_ok, agent_success, done).

    Policy:
    - env_ok: True iff env preflight passed (for exploit workflows). For workflows without
      preflight, env_ok=True.
    - agent_success: True iff workflow log reports workflow_summary.success==True.
    - done: True ONLY when the run reached a terminal "agent outcome" (success or failure)
      and there is no env/framework/setup error. Any non-agent error => done=False.
    """
    wf_complete = _extract_workflow_complete_from_log(saved_log_path)
    wf_success = _extract_workflow_success_from_log(saved_log_path)

    requires_preflight = _workflow_requires_env_preflight(workflow)
    if requires_preflight:
        env_preflight = _extract_env_preflight_from_log(saved_log_path)
        env_ok = env_preflight.get("passed") is True
    else:
        env_ok = True

    agent_success = wf_success is True

    # If workflow didn't even mark complete, it's a framework/setup interruption -> undone.
    if wf_complete is not True:
        return env_ok, agent_success, False

    # If preflight is required and did not pass, it's an env/framework issue -> undone.
    if requires_preflight and not env_ok:
        return env_ok, agent_success, False

    # If we can't read the workflow success signal, treat as framework/logging issue -> undone.
    if wf_success is None:
        return env_ok, False, False

    # If the workflow says success=False, that's an agent failure -> done.
    if wf_success is False:
        return env_ok, False, True

    # wf_success is True: normally done, but if process return_code is non-zero, that's inconsistent
    # and treated as framework error -> undone.
    if return_code != 0:
        return env_ok, True, False

    return env_ok, True, True


def build_cmd(
    *,
    workflow: str,
    task_dir_name: str,
    bounty_number: str,
    model: str,
    iterations: int,
    max_input_tokens: int,
    max_output_tokens: int,
    logging_level: str,
) -> List[str]:
    return [
        sys.executable,
        "-m",
        "workflows.runner",
        "--workflow-type",
        workflow,
        "--task_dir",
        f"bountytasks/{task_dir_name}",
        "--bounty_number",
        str(bounty_number),
        "--model",
        model,
        "--max_input_tokens",
        str(max_input_tokens),
        "--max_output_tokens",
        str(max_output_tokens),
        "--phase_iterations",
        str(iterations),
        "--logging_level",
        logging_level,
    ]


def run_and_tee(cmd: List[str], combined_out_path: Path) -> Tuple[int, str]:
    """
    Run cmd, stream output to console, and write combined stdout+stderr to file.
    Returns (return_code, combined_text).
    """
    combined_out_path.parent.mkdir(parents=True, exist_ok=True)
    with combined_out_path.open("w", encoding="utf-8", errors="replace") as f:
        # Merge stderr into stdout to preserve order.
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=CWD,
            env=os.environ.copy(),
        )
        assert p.stdout is not None
        buf: List[str] = []
        for line in p.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            f.write(line)
            buf.append(line)
        rc = p.wait()
        combined = "".join(buf)
        return rc, combined


def run_and_capture(cmd: List[str], combined_out_path: Path) -> Tuple[int, str]:
    """
    Run cmd and capture combined stdout+stderr, writing it to combined_out_path.
    Returns (return_code, combined_text).

    This is used for parallel runs to avoid interleaved live output on the console.
    """
    combined_out_path.parent.mkdir(parents=True, exist_ok=True)
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        cwd=CWD,
        env=os.environ.copy(),
    )
    combined = p.stdout or ""
    combined_out_path.write_text(combined, encoding="utf-8", errors="replace")
    return p.returncode, combined


def run_one(
    *,
    t: Target,
    order_index: int,
    workflow: str,
    model: str,
    iterations: int,
    max_input_tokens: int,
    max_output_tokens: int,
    logging_level: str,
    run_dir: Path,
    live_output: bool,
) -> Result:
    cmd = build_cmd(
        workflow=workflow,
        task_dir_name=t.task_dir_name,
        bounty_number=t.bounty_number,
        model=model,
        iterations=iterations,
        max_input_tokens=max_input_tokens,
        max_output_tokens=max_output_tokens,
        logging_level=logging_level,
    )

    started = dt.datetime.now(dt.timezone.utc)
    t0 = time.time()
    combined_out = run_dir / "per_bounty_logs" / f"{order_index:04d}_{_safe_name(t.key)}.log"

    repo_lock = _get_repo_lock(t.task_dir_name)
    if not repo_lock.acquire(blocking=False):
        print(f"--- repo-lock: waiting on {t.task_dir_name} (avoid concurrent git checkout) ---")
        repo_lock.acquire()
    try:
        print(f"--- repo-lock: acquired {t.task_dir_name} ---")
        # Preflight: clear stale git lock files for this repo (handles submodule gitdirs).
        _clear_stale_git_locks_for_task(t.task_dir_name)
        if live_output:
            rc, combined_text = run_and_tee(cmd, combined_out)
        else:
            rc, combined_text = run_and_capture(cmd, combined_out)
    finally:
        repo_lock.release()
        print(f"--- repo-lock: released {t.task_dir_name} ---")

    dur = time.time() - t0
    finished = dt.datetime.now(dt.timezone.utc)

    saved_log = _strip_ansi(_extract_first(LOG_SAVED_RE, combined_text, "path"))
    archived_log = _strip_ansi(_extract_first(LOG_ARCHIVE_RE, combined_text, "path"))
    error_reason = _extract_error_reason(combined_text)

    # Compute env/agent/done from the workflow JSON log.
    env_ok, agent_success, done = _classify_run(
        workflow=workflow, return_code=rc, saved_log_path=saved_log
    )

    # If we consider it "undone", ensure the outer runner sees this as a failure.
    # (But keep agent failure semantics as "done" so resume won't rerun it.)
    if not done and rc == 0:
        rc = 1

    # Ensure we still propagate a helpful reason in common cases.
    if not error_reason:
        if _workflow_requires_env_preflight(workflow) and not env_ok:
            env_preflight = _extract_env_preflight_from_log(saved_log)
            detail = env_preflight.get("error_reason") or "unknown"
            error_reason = f"env preflight failed: {detail}"
        elif not done:
            error_reason = "workflow did not complete successfully (framework/setup error)"
        elif not agent_success:
            error_reason = "agent did not solve the task"

    # Keep these for debugging / analysis even though env_ok/agent_success/done are the new flags.
    env_preflight = _extract_env_preflight_from_log(saved_log)
    workflow_success = _extract_workflow_success_from_log(saved_log)

    return Result(
        key=t.key,
        task_dir_name=t.task_dir_name,
        bounty_number=t.bounty_number,
        bounty_path=t.bounty_path,
        workflow=workflow,
        model=model,
        phase_iterations=iterations,
        max_input_tokens=max_input_tokens,
        max_output_tokens=max_output_tokens,
        logging_level=logging_level,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
        duration_s=dur,
        return_code=rc,
        env_ok=env_ok,
        agent_success=agent_success,
        done=done,
        saved_log_path=saved_log,
        archived_log_path=archived_log,
        error_reason=error_reason,
        combined_output_file=str(combined_out),
        env_preflight_passed=env_preflight.get("passed"),
        env_preflight_error_reason=env_preflight.get("error_reason"),
        env_preflight_verify_before_exit_code=env_preflight.get(
            "verify_before_exit_code"
        ),
        env_preflight_verify_after_exit_code=env_preflight.get("verify_after_exit_code"),
        workflow_success=workflow_success,
    )


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path(CWD))
    ap.add_argument(
        "--glob",
        dest="glob_pattern",
        default="bountytasks/*/bounties/bounty_*",
        help="Glob (relative to --root) selecting bounty directories",
    )
    ap.add_argument("--workflow", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--iterations", type=int, default=50)
    ap.add_argument("--max-input-tokens", type=int, default=8192)
    ap.add_argument("--max-output-tokens", type=int, default=8192)
    ap.add_argument("--logging-level", default="INFO")
    ap.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of parallel workers (1 = sequential with live console output)",
    )
    resume_mode = ap.add_mutually_exclusive_group()
    resume_mode.add_argument(
        "--resume",
        dest="resume",
        action="store_true",
        default=True,
        help="Skip already-successful runs (default)",
    )
    resume_mode.add_argument(
        "--no-resume",
        dest="resume",
        action="store_false",
        help="Disable resume; always run every bounty",
    )

    rerun_mode = ap.add_mutually_exclusive_group()
    rerun_mode.add_argument(
        "--rerun-failures",
        dest="rerun_failures",
        action="store_true",
        default=True,
        help="When used with --resume, rerun failures too (default)",
    )
    rerun_mode.add_argument(
        "--no-rerun-failures",
        dest="rerun_failures",
        action="store_false",
        help="When used with --resume, skip previous failures",
    )

    fail_mode = ap.add_mutually_exclusive_group()
    fail_mode.add_argument(
        "--continue-on-fail",
        dest="continue_on_fail",
        action="store_true",
        default=True,
        help="Continue running even if a bounty run fails (default)",
    )
    fail_mode.add_argument(
        "--stop-on-fail",
        dest="continue_on_fail",
        action="store_false",
        help="Stop the whole loop when a bounty run fails",
    )
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args(argv)
    if args.workers < 1:
        print("--workers must be >= 1", file=sys.stderr)
        return 2

    root = args.root.resolve()
    if not root.exists():
        print(f"Root does not exist: {root}", file=sys.stderr)
        return 2

    run_dir = root / "run_results" / f"run_all_{_safe_name(args.workflow)}_{_safe_name(args.model)}"
    run_dir.mkdir(parents=True, exist_ok=True)
    results_file = run_dir / "results.jsonl"
    state_file = run_dir / "state.json"

    state = load_state(state_file) if args.resume else {}

    targets = list(iter_bounties(root, args.glob_pattern))
    if args.limit is not None:
        targets = targets[: args.limit]

    total = len(targets)
    print(f"Found {total} bounties. Output dir: {run_dir}")
    print(f"Results: {results_file}")
    print(f"State:   {state_file}")
    if args.workers > 1:
        print(f"Workers: {args.workers} (parallel; per-bounty output is captured into per_bounty_logs/*.log)")

    def _prev_is_done(prev: dict) -> bool:
        # New format: explicit done flag.
        if "done" in prev:
            return bool(prev.get("done"))

        # Back-compat: infer from the workflow log if available.
        saved_log = _strip_ansi(prev.get("saved_log_path"))
        workflow = str(prev.get("workflow") or "")
        try:
            # Use return_code from state if present; default nonzero to avoid misclassifying.
            rc = int(prev.get("return_code", 1))
        except Exception:
            rc = 1

        # If there's no log path, we cannot prove it's done -> rerun.
        if not saved_log:
            return False

        _env_ok, _agent_success, done = _classify_run(
            workflow=workflow, return_code=rc, saved_log_path=saved_log
        )
        return done

    # Only rerun undone tasks.
    jobs: List[Tuple[int, Target]] = []
    for i, t in enumerate(targets, start=1):
        prev = state.get(t.key)
        if args.resume and prev and _prev_is_done(prev):
            print(f"[{i}/{total}] SKIP (already done): {t.key}")
            continue
        jobs.append((i, t))

    if args.workers == 1:
        # Sequential: preserve existing behavior including live output to console.
        for i, t in jobs:
            print(f"\n=== [{i}/{total}] RUN {t.key} ===")
            cmd_preview = build_cmd(
                workflow=args.workflow,
                task_dir_name=t.task_dir_name,
                bounty_number=t.bounty_number,
                model=args.model,
                iterations=args.iterations,
                max_input_tokens=args.max_input_tokens,
                max_output_tokens=args.max_output_tokens,
                logging_level=args.logging_level,
            )
            print("CMD:", " ".join(shlex.quote(x) for x in cmd_preview))

            r = run_one(
                t=t,
                order_index=i,
                workflow=args.workflow,
                model=args.model,
                iterations=args.iterations,
                max_input_tokens=args.max_input_tokens,
                max_output_tokens=args.max_output_tokens,
                logging_level=args.logging_level,
                run_dir=run_dir,
                live_output=True,
            )

            with results_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")
            state[t.key] = asdict(r)
            save_state(state_file, state)

            status = _format_env_agent_status(r)
            print(
                f"=== [{i}/{total}] {status} {t.key} | saved_log= {r.saved_log_path} | archived= {r.archived_log_path} | full_log= {r.combined_output_file}"
            )
            if (not r.agent_success) and r.error_reason:
                print(f"=== reason: {r.error_reason}")

            # Stop-on-fail should stop on env/framework errors (done==False) or agent failure, per rc.
            if (not r.done) and (not args.continue_on_fail):
                print("Stopping early (use --continue-on-fail to keep going).", file=sys.stderr)
                return r.return_code if r.return_code != 0 else 1
    else:
        # Parallel: run multiple bounties concurrently.
        # Note: we avoid live streaming output to prevent interleaved console logs; output is captured per bounty.
        first_failure_rc: Optional[int] = None

        with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
            # Important: do NOT submit all jobs at once.
            #
            # If we do, multiple worker threads will immediately pick up jobs from the same repo and
            # then block on the per-repo lock inside run_one(), effectively wasting workers and
            # destroying throughput. Instead, we keep at most one in-flight job per repo and dispatch
            # work from other repos first.

            # Preserve stable repo order based on first appearance in the job list.
            repo_queues: Dict[str, deque[Tuple[int, Target]]] = {}
            repos_in_order: List[str] = []
            for i, t in jobs:
                print(f"=== [{i}/{total}] QUEUE {t.key} ===")
                if t.task_dir_name not in repo_queues:
                    repo_queues[t.task_dir_name] = deque()
                    repos_in_order.append(t.task_dir_name)
                repo_queues[t.task_dir_name].append((i, t))

            future_to_job: Dict[cf.Future[Result], Tuple[int, Target]] = {}
            busy_repos: set[str] = set()
            repo_cursor = 0

            def _dispatch_ready_jobs() -> None:
                """Submit jobs until workers are full or no non-busy repo has pending work."""
                nonlocal repo_cursor
                if not repos_in_order:
                    return

                while len(future_to_job) < args.workers:
                    found = False
                    # Round-robin to avoid starving repos later in the list.
                    for _ in range(len(repos_in_order)):
                        repo = repos_in_order[repo_cursor]
                        repo_cursor = (repo_cursor + 1) % len(repos_in_order)
                        if repo in busy_repos:
                            continue
                        q = repo_queues.get(repo)
                        if not q:
                            continue
                        if len(q) == 0:
                            continue
                        i, t = q.popleft()
                        busy_repos.add(repo)
                        print(f"=== [{i}/{total}] DISPATCH {t.key} ===")
                        fut = ex.submit(
                            run_one,
                            t=t,
                            order_index=i,
                            workflow=args.workflow,
                            model=args.model,
                            iterations=args.iterations,
                            max_input_tokens=args.max_input_tokens,
                            max_output_tokens=args.max_output_tokens,
                            logging_level=args.logging_level,
                            run_dir=run_dir,
                            live_output=False,
                        )
                        future_to_job[fut] = (i, t)
                        found = True
                        break
                    if not found:
                        return

            _dispatch_ready_jobs()

            while future_to_job:
                done, _ = cf.wait(future_to_job, return_when=cf.FIRST_COMPLETED)
                for fut in done:
                    i, t = future_to_job.pop(fut)
                    busy_repos.discard(t.task_dir_name)
                    try:
                        r = fut.result()
                    except Exception as e:  # noqa: BLE001  # pylint: disable=broad-exception-caught
                        # Treat unexpected worker exceptions as failures.
                        now = dt.datetime.now(dt.timezone.utc).isoformat()
                        r = Result(
                            key=t.key,
                            task_dir_name=t.task_dir_name,
                            bounty_number=t.bounty_number,
                            bounty_path=t.bounty_path,
                            workflow=args.workflow,
                            model=args.model,
                            phase_iterations=args.iterations,
                            max_input_tokens=args.max_input_tokens,
                            max_output_tokens=args.max_output_tokens,
                            logging_level=args.logging_level,
                            started_at=now,
                            finished_at=now,
                            duration_s=0.0,
                            return_code=1,
                            env_ok=False,
                            agent_success=False,
                            done=False,
                            saved_log_path=None,
                            archived_log_path=None,
                            error_reason=f"runner exception: {e!r}",
                            combined_output_file=str(
                                run_dir / "per_bounty_logs" / f"{i:04d}_{_safe_name(t.key)}.log"
                            ),
                            env_preflight_passed=None,
                            env_preflight_error_reason=None,
                            env_preflight_verify_before_exit_code=None,
                            env_preflight_verify_after_exit_code=None,
                            workflow_success=None,
                        )

                    with results_file.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")
                    state[t.key] = asdict(r)
                    save_state(state_file, state)

                    status = _format_env_agent_status(r)
                    print(
                        f"=== [{i}/{total}] {status} {t.key} | saved_log= {r.saved_log_path} | archived= {r.archived_log_path} | full_log= {r.combined_output_file}"
                    )
                    if (not r.agent_success) and r.error_reason:
                        print(f"=== reason: {r.error_reason}")

                    if (not r.done) and (not args.continue_on_fail) and first_failure_rc is None:
                        first_failure_rc = r.return_code if r.return_code != 0 else 1
                        # Stop dispatching new jobs; best-effort cancel not-yet-started futures.
                        for pending in future_to_job:
                            pending.cancel()
                        # Also drop any still-pending queued jobs.
                        repo_queues.clear()

                if first_failure_rc is None:
                    _dispatch_ready_jobs()

        if first_failure_rc is not None:
            print("Stopping early due to failure (use --continue-on-fail to keep going).", file=sys.stderr)
            return first_failure_rc

    print("\nDone.")
    return 0


if __name__ == "__main__":
    main(sys.argv[1:])
