"""Dedup manual scans + resilient runner-detail lookup."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from src.runner.registry import approve_runner, register_runner
from src.runner.storage import generate_registration_token, read_runner
from src.sources.triggers import dispatch_source_scan


def _connection():
    return {
        "auth": {"orgOrOwner": "dedup-org", "token": "t"},
        "sourceType": "github",
        "category": "code-repositories",
        "discoveredItems": ["dedup-org/repo"],
        "scanners": [],
    }


def test_dispatch_is_blocked_when_a_scan_is_already_in_flight():
    with patch("src.runner.jobs.has_active_jobs_for_org", return_value=True):
        with pytest.raises(ValueError, match="already in progress"):
            dispatch_source_scan(_connection())


def test_read_runner_resolves_a_bare_hash_id():
    raw_reg, _ = generate_registration_token()
    runner, _auth, err = register_runner(raw_token=raw_reg, name="lookup-runner", os_name="linux", arch="x86_64")
    assert err is None
    approve_runner(runner["id"])
    full_id = runner["id"]                       # "runner-<hash>"
    bare = full_id.removeprefix("runner-")       # the stripped form the URL uses
    assert read_runner(bare) is not None         # resolves despite the missing prefix
    assert read_runner(full_id) is not None
