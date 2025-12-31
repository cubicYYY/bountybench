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
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


LOG_SAVED_RE = re.compile(r"Saved log to:\s*(?P<path>\S+)")
LOG_ARCHIVE_RE = re.compile(r"Archiving log to:\s*(?P<path>\S+)")
WORKFLOW_ERROR_RE = re.compile(r"Error in (?P<wf>\S+) workflow:\s*(?P<msg>.+)")


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
    success: bool
    saved_log_path: Optional[str]
    archived_log_path: Optional[str]
    error_reason: Optional[str]
    combined_output_file: str


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
            cwd="/home/kali/bountybench",
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
        cwd="/home/kali/bountybench",
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

    if live_output:
        rc, combined_text = run_and_tee(cmd, combined_out)
    else:
        rc, combined_text = run_and_capture(cmd, combined_out)

    dur = time.time() - t0
    finished = dt.datetime.now(dt.timezone.utc)

    saved_log = _extract_first(LOG_SAVED_RE, combined_text, "path")
    archived_log = _extract_first(LOG_ARCHIVE_RE, combined_text, "path")
    error_reason = _extract_error_reason(combined_text)
    success = (rc == 0)

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
        success=success,
        saved_log_path=saved_log,
        archived_log_path=archived_log,
        error_reason=error_reason,
        combined_output_file=str(combined_out),
    )


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path("/home/kali/bountybench"))
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

    # Pre-filter targets based on resume/rerun flags, but preserve stable ordering indexes.
    #
    # When resuming and rerunning failures, we queue previously-failed bounties *last* so
    # fresh/unknown bounties run first (useful for long runs where you'd rather spend early
    # time on new work than immediately retrying known failures).
    jobs_fresh: List[Tuple[int, Target]] = []
    jobs_failed: List[Tuple[int, Target]] = []
    for i, t in enumerate(targets, start=1):
        prev = state.get(t.key)
        if args.resume and prev:
            prev_success = bool(prev.get("success"))
            if prev_success:
                print(f"[{i}/{total}] SKIP (already success): {t.key}")
                continue
            if not args.rerun_failures:
                print(f"[{i}/{total}] SKIP (previous failure, rerun disabled): {t.key}")
                continue
            # Rerun this failure, but push it to the end of the queue.
            jobs_failed.append((i, t))
            continue
        jobs_fresh.append((i, t))

    jobs: List[Tuple[int, Target]] = jobs_fresh + jobs_failed

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

            status = "OK" if r.success else f"FAIL(rc={r.return_code})"
            print(
                f"=== [{i}/{total}] {status} {t.key} | saved_log={r.saved_log_path} | archived={r.archived_log_path}"
            )
            if (not r.success) and r.error_reason:
                print(f"=== reason: {r.error_reason}")

            if (not r.success) and (not args.continue_on_fail):
                print("Stopping early (use --continue-on-fail to keep going).", file=sys.stderr)
                return r.return_code if r.return_code != 0 else 1
    else:
        # Parallel: run multiple bounties concurrently.
        # Note: we avoid live streaming output to prevent interleaved console logs; output is captured per bounty.
        first_failure_rc: Optional[int] = None

        with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
            future_to_job: Dict[cf.Future[Result], Tuple[int, Target]] = {}
            for i, t in jobs:
                print(f"=== [{i}/{total}] QUEUE {t.key} ===")
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

            for fut in cf.as_completed(future_to_job):
                i, t = future_to_job[fut]
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
                        success=False,
                        saved_log_path=None,
                        archived_log_path=None,
                        error_reason=f"runner exception: {e!r}",
                        combined_output_file=str(
                            run_dir / "per_bounty_logs" / f"{i:04d}_{_safe_name(t.key)}.log"
                        ),
                    )

                with results_file.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")
                state[t.key] = asdict(r)
                save_state(state_file, state)

                status = "OK" if r.success else f"FAIL(rc={r.return_code})"
                print(
                    f"=== [{i}/{total}] {status} {t.key} | saved_log={r.saved_log_path} | archived={r.archived_log_path}"
                )
                if (not r.success) and r.error_reason:
                    print(f"=== reason: {r.error_reason}")

                if (not r.success) and (not args.continue_on_fail) and first_failure_rc is None:
                    first_failure_rc = r.return_code if r.return_code != 0 else 1
                    # Best-effort: cancel futures that haven't started yet.
                    for pending in future_to_job:
                        pending.cancel()

        if first_failure_rc is not None:
            print("Stopping early due to failure (use --continue-on-fail to keep going).", file=sys.stderr)
            return first_failure_rc

    print("\nDone.")
    return 0


if __name__ == "__main__":
    main(sys.argv[1:])
