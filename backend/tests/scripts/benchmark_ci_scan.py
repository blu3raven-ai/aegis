"""End-to-end timing for a CI-triggered scan.

Submits a scan via /api/v1/scans/trigger and polls the scan run until terminal
status, measuring wall-clock time across submit / queued / running / completed.

Usage:
    python backend/tests/scripts/benchmark_ci_scan.py \
        --aegis-url http://localhost:8000 \
        --api-key <scan:trigger key> \
        --source-id acme/repo \
        --base-sha <sha> --commit-sha <sha> \
        --pr-number 42 \
        --output benchmark.json

Output:
    JSON file with: { config, timings: {submit_to_queued, queued_to_running,
    running_to_completed, total}, scan_id, status }.

Designed to be re-run with --scan-scope=full_tree (no --pr-number) for a
baseline comparison.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import httpx


def submit_scan(*, aegis_url, api_key, source_id, commit_sha, branch, pr_number):
    body = {
        "source_id": source_id,
        "commit_sha": commit_sha,
        "branch": branch,
    }
    if pr_number is not None:
        body["pr_number"] = pr_number

    t0 = time.monotonic()
    resp = httpx.post(
        f"{aegis_url}/api/v1/scans/trigger",
        json=body,
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30.0,
    )
    submit_elapsed = time.monotonic() - t0
    resp.raise_for_status()
    payload = resp.json()
    return payload["scan_id"], submit_elapsed


def poll_until_terminal(*, aegis_url, api_key, scan_id, timeout_seconds, poll_interval):
    """Poll /scans/{id} until status is one of {completed, failed, cancelled}.

    Returns (final_status, timings) where timings records when we first saw
    each status transition (relative to the start of polling).
    """
    deadline = time.monotonic() + timeout_seconds
    seen = {"queued": None, "running": None, "completed": None, "failed": None, "cancelled": None}
    start = time.monotonic()

    while time.monotonic() < deadline:
        resp = httpx.get(
            f"{aegis_url}/api/v1/scans/{scan_id}",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10.0,
        )
        if resp.status_code == 404:
            raise RuntimeError(f"scan {scan_id} not found (404)")
        resp.raise_for_status()
        status = resp.json().get("status")
        if status in seen and seen[status] is None:
            seen[status] = time.monotonic() - start

        if status in ("completed", "failed", "cancelled"):
            return status, seen
        time.sleep(poll_interval)

    raise TimeoutError(f"scan {scan_id} did not reach terminal state in {timeout_seconds}s")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--aegis-url", required=True)
    p.add_argument("--api-key", required=True)
    p.add_argument("--source-id", required=True, help="repo identifier, e.g. owner/repo")
    p.add_argument("--commit-sha", required=True)
    p.add_argument("--branch", default="main")
    p.add_argument("--pr-number", type=int, default=None,
                   help="Set to trigger diff-scoped mode; omit for full-tree baseline.")
    p.add_argument("--base-sha", default=None,
                   help="Reserved for callers that want to validate the base SHA the backend resolved. Not sent in the trigger body.")
    p.add_argument("--timeout", type=int, default=600, help="seconds to wait for terminal status")
    p.add_argument("--poll-interval", type=float, default=2.0)
    p.add_argument("--output", required=True, help="path to write benchmark JSON")
    args = p.parse_args(argv)

    print(f"submitting scan for {args.source_id} @ {args.commit_sha}"
          f" (pr={args.pr_number}, mode={'diff_scoped' if args.pr_number else 'full_tree'})")

    scan_id, submit_elapsed = submit_scan(
        aegis_url=args.aegis_url,
        api_key=args.api_key,
        source_id=args.source_id,
        commit_sha=args.commit_sha,
        branch=args.branch,
        pr_number=args.pr_number,
    )
    print(f"submitted scan_id={scan_id} submit_elapsed={submit_elapsed:.2f}s")

    try:
        final_status, seen = poll_until_terminal(
            aegis_url=args.aegis_url,
            api_key=args.api_key,
            scan_id=scan_id,
            timeout_seconds=args.timeout,
            poll_interval=args.poll_interval,
        )
    except TimeoutError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    timings = {
        "submit_to_queued":      seen["queued"],
        "queued_to_running":     (seen["running"] - seen["queued"]) if seen["running"] and seen["queued"] else None,
        "running_to_completed":  (seen["completed"] - seen["running"]) if seen["completed"] and seen["running"] else None,
        "total_polling_seconds": seen["completed"] or seen["failed"] or seen["cancelled"],
    }

    result = {
        "config": {
            "source_id": args.source_id,
            "commit_sha": args.commit_sha,
            "pr_number": args.pr_number,
            "mode": "diff_scoped" if args.pr_number else "full_tree",
        },
        "scan_id": scan_id,
        "final_status": final_status,
        "submit_elapsed_seconds": submit_elapsed,
        "timings": timings,
    }

    Path(args.output).write_text(json.dumps(result, indent=2))
    print(f"wrote {args.output}")
    if final_status != "completed":
        print(f"WARNING: final status is {final_status}, not completed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
