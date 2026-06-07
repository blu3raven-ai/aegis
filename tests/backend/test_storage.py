import pytest
import src.shared.config as config
from src.shared.paths import normalize_org, parse_org_values
from src.storage import combine_secrets_snapshots, empty_dependencies_snapshot, empty_secrets_snapshot

@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    config_path = tmp_path / "data" / "config" / "current.json"
    history_path = tmp_path / "data" / "config" / "history.jsonl"
    env_path = tmp_path / ".env.local"

    monkeypatch.setattr(config, "ENV_PATH", env_path)
    
    import src.settings.roles_store as roles_store
    roles_path = tmp_path / "data" / "settings" / "roles.json"

    monkeypatch.setenv("RUNNER_ENCRYPTION_KEY", "a" * 64)
    monkeypatch.setenv("FASTAPI_ENV", "production")

    return {
        "config_path": config_path,
        "history_path": history_path,
    }

def _b64url(data: bytes | str) -> str:
    import base64
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def _make_jwt(sub: str, role: str, secret: str = "a" * 64) -> str:
    import hashlib
    import hmac
    import json
    import time
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}))
    payload = _b64url(json.dumps({"sub": sub, "role": role, "iat": now, "exp": now + 60}))
    key = bytes.fromhex(secret) if len(secret) == 64 else secret.encode("utf-8")
    signature = _b64url(hmac.new(key, f"{header}.{payload}".encode("utf-8"), hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"

def auth_headers(role: str = "owner", sub: str = "usr_admin", secret: str = "a" * 64) -> dict[str, str]:
    return {"Authorization": f"Bearer {_make_jwt(sub=sub, role=role, secret=secret)}"}

def test_parse_org_values_splits_and_dedupes_case_insensitively():
    assert parse_org_values(["example-org,Example-Labs", "example-org"]) == ["example-org", "Example-Labs"]


def test_normalize_org_matches_snapshot_filename_policy():
    assert normalize_org("aegis/Labs") == "aegis_labs"


def test_empty_snapshots_match_next_response_shape():
    dependencies = empty_dependencies_snapshot("example-org")
    secrets = empty_secrets_snapshot("example-org")

    assert dependencies["meta"]["org"] == "example-org"
    assert dependencies["alerts"] == []
    assert "analytics" in dependencies
    assert secrets["meta"]["organization"] == "example-org"
    assert secrets["stats"]["actionTakenCount"] == 0
    assert secrets["findings"] == []


def test_combine_secrets_snapshots_preserves_findings_and_counts_statuses():
    snapshot = combine_secrets_snapshots(
        ["example-org", "example-labs"],
        [
            {
                "meta": {"lastUpdatedAt": "2026-04-01T00:00:00.000Z"},
                "findings": [
                    {"organization": "example-org", "repository": "repo-a", "source": "betterleaks", "reviewStatus": "new"},
                    {"organization": "example-org", "repository": "repo-a", "source": "trufflehog", "reviewStatus": "confirmed"},
                ],
            },
            {
                "meta": {"lastUpdatedAt": "2026-04-02T00:00:00.000Z"},
                "findings": [
                    {"organization": "example-labs", "repository": "repo-b", "source": "betterleaks", "reviewStatus": "action_taken"},
                ],
            },
        ],
    )

    assert snapshot["meta"]["organization"] == "example-org,example-labs"
    assert snapshot["meta"]["lastUpdatedAt"] == "2026-04-02T00:00:00.000Z"
    assert snapshot["stats"]["total"] == 3
    assert snapshot["stats"]["newCount"] == 1
    assert snapshot["stats"]["confirmedCount"] == 1
    assert snapshot["stats"]["actionTakenCount"] == 1




def test_config_resolves_token_from_source_connections(monkeypatch):
    import src.shared.config as config

    # Mock _read_source_connections to return a fake connection
    monkeypatch.setattr(config, "_read_source_connections", lambda: [
        {
            "id": "src_1",
            "category": "code-repositories",
            "sourceType": "github",
            "status": "connected",
            "auth": {"orgOrOwner": "example-labs", "token": "aegis-token"},
            "scanScope": "all",
            "excludedItems": [],
            "discoveredItems": ["repo-a"],
        },
    ])

    assert config.get_github_token_for_org("example-labs") == "aegis-token"


def test_secret_run_storage_matches_next_run_shape_and_keeps_progress_monotonic(tmp_path, monkeypatch):
    import src.storage as storage

    run = storage.create_secret_run("Example-Labs", "sr-run-1")
    assert run["organization"] == "example-labs"
    assert run["status"] == "queued"
    assert run["progress"] == {
        "expectedRepos": None,
        "scannedRepos": 0,
        "finishedRepos": 0,
        "percent": 0,
        "currentRepo": None,
        "currentClassifying": None,
        "stage": "queued",
    }

    updated = storage.update_secret_run("Example-Labs", "sr-run-1", {"progress": {"percent": 70, "stage": "scanning"}})
    assert updated["progress"]["percent"] == 70
    updated_again = storage.update_secret_run("Example-Labs", "sr-run-1", {"progress": {"percent": 50, "stage": "scanning"}})
    assert updated_again["progress"]["percent"] == 70


def test_run_state_transition_guards_and_idempotent_transition():
    from src.secrets.scanner import apply_run_transition, can_transition_run_status

    current = {"id": "run-1", "status": "queued", "lastHeartbeatAt": None}
    assert can_transition_run_status("queued", "running") is True
    assert can_transition_run_status("completed", "running") is False
    assert can_transition_run_status("ingesting", "completed_with_merge_error") is True
    assert can_transition_run_status("completed_with_merge_error", "running") is False

    running = apply_run_transition(current, "running", {"startedAt": "2026-04-01T00:00:00.000Z"})
    assert running is not None
    assert running["status"] == "running"
    assert running["lastStatusTransitionAt"]
    assert running["lastHeartbeatAt"]

    same = apply_run_transition(running, "running", {"lastHeartbeatAt": "custom-heartbeat"})
    assert same is not None
    assert same["status"] == "running"
    assert same["lastHeartbeatAt"] == "custom-heartbeat"
    assert apply_run_transition({"status": "completed"}, "running") is None


def test_scan_runtime_pure_helpers_match_next_docker_contract():
    from src.secrets.scanner import (
        compute_running_percent,
        extract_repo_progress,
        parse_progress_from_lines,
    )

    assert extract_repo_progress("[+] Scanning repo: example-org/app") == {"type": "scanning", "repo": "example-org/app"}
    assert extract_repo_progress("[✓] Finished example-org/app — 0 finding file(s) in 2s") == {"type": "finished", "repo": "example-org/app"}
    assert compute_running_percent(10, 3, 2) == 18.8

    progress = parse_progress_from_lines(
        [
            "[+] Scanning repo: example-org/app",
            "[✓] Finished example-org/app — 0 finding file(s) in 2s",
            "Normalizing results for organization example-org",
        ],
        {"scannedRepos": 0, "finishedRepos": 0, "currentRepo": None, "stage": "queued", "percent": 1},
    )
    assert progress["scannedRepos"] == 1
    assert progress["finishedRepos"] == 1
    assert progress["currentRepo"] is None
    assert progress["stage"] == "ingesting"


def test_parse_progress_from_lines_reconciles_expected_repos_when_scanner_finishes_more_than_predicted():
    from src.secrets.scanner import parse_progress_from_lines

    progress = parse_progress_from_lines(
        [
            "[✓] Finished example-org/repo-a — 0 finding file(s) in 2s",
            "[✓] Finished example-org/repo-b — 1 finding file(s) in 3s",
            "[✓] Finished example-org/repo-c — 0 finding file(s) in 1s",
            "[✓] Finished example-org/repo-d — 2 finding file(s) in 5s",
        ],
        {"expectedRepos": 3, "scannedRepos": 0, "finishedRepos": 0, "currentRepo": None, "stage": "queued", "percent": 1},
    )

    assert progress["finishedRepos"] == 4
    assert progress["expectedRepos"] == 4


def test_ingest_normalized_jsonl_writes_findings_to_db(tmp_path, monkeypatch):
    from src.secrets.scanner import ingest_normalized_jsonl


    source = tmp_path / "example-org_normalized.jsonl"
    source.write_text(
        '{"source":"betterleaks","repository":"repo-a","DetectorName":"generic-api-key","Secret":"secret-value","File":"src/app.py","line":12,"Commit":"abc123","Date":"2026-04-01T00:00:00Z"}\n',
        encoding="utf-8",
    )

    # ingest_normalized_jsonl now returns (None, repo_to_sha) — snapshot is built from DB
    result, repo_to_sha = ingest_normalized_jsonl("example-org", "ingest-run-1", source)

    assert result is None  # snapshot no longer returned directly
    assert repo_to_sha == {"repo-a": "abc123"}

    # Verify findings were written to DB
    import src.storage as storage
    snapshot = storage.read_secrets_snapshot("example-org")
    assert snapshot is not None
    assert snapshot["meta"]["organization"] == "example-org"
    assert snapshot["stats"]["total"] >= 1


def test_ingest_raw_scanner_output_reads_betterleaks_and_trufflehog_shapes(tmp_path, monkeypatch):
    from src.secrets.scanner import ingest_raw_scanner_output


    repo_dir = tmp_path / "raw" / "example-org" / "repo-a"
    repo_dir.mkdir(parents=True)
    (repo_dir / "betterleaks.json").write_text(
        '[{"DetectorName":"generic-api-key","Secret":"secret-a","File":"a.py","line":1,"Commit":"aaa"}]',
        encoding="utf-8",
    )
    (repo_dir / "trufflehog.json").write_text(
        '{"DetectorName":"gcp-api-key","Raw":"secret-b","SourceMetadata":{"Data":{"Git":{"file":"b.py","commit":"bbb","line":2}}}}\n',
        encoding="utf-8",
    )

    # ingest_raw_scanner_output now returns (None, repo_to_sha)
    result, repo_to_sha = ingest_raw_scanner_output("example-org", "run-raw", tmp_path / "raw" / "example-org")

    assert result is None
    assert repo_to_sha["repo-a"] in {"aaa", "bbb"}


def test_in_memory_scan_runtime_tracks_probe_and_cancel_metadata():
    from src.secrets.scanner import InMemoryScanRuntime

    runtime = InMemoryScanRuntime()
    assert runtime.probe("example-org") == {"active": False, "runId": None, "containerName": None, "childPid": None}
    assert runtime.start("example-org", "run-1") is True
    assert runtime.start("EXAMPLE-ORG", "run-2") is False
    runtime.set_process_meta("example-org", container_name="container-1", child_pid=123)
    assert runtime.probe("example-org") == {"active": True, "runId": "run-1", "containerName": "container-1", "childPid": 123}

    cancelled = []
    result = runtime.cancel("example-org", lambda job: cancelled.append((job.run_id, job.container_name, job.child_pid)))
    assert result == {"ok": True, "runId": "run-1"}
    assert cancelled == [("run-1", "container-1", 123)]
    assert runtime.is_cancelled("run-1") is True
    runtime.release("example-org")
    assert runtime.is_cancelled("run-1") is False
    assert runtime.cancel("example-org") == {"ok": False, "reason": "no_active_run"}


def test_execute_secret_scan_once_refuses_duplicate_runtime_start(tmp_path, monkeypatch):
    import src.storage as storage
    from src.secrets.scanner import InMemoryScanRuntime, execute_secret_scan_once

    runtime = InMemoryScanRuntime()
    assert runtime.start("example-org", "already-running") is True

    run = execute_secret_scan_once(
        "example-org",
        "token",
        "run-duplicate",
        scanner_config={"image": "github-secrets", "concurrency": "4", "scanStartDate": ""},
        runtime=runtime,
    )

    assert run is None
    assert storage.read_secret_run("example-org", "run-duplicate") is None
    runtime.release("example-org")


# ============================================================================
# Dependencies (Software Composition Analysis) Tests
# ============================================================================


def test_dependencies_analytics_counts_correctly():
    from src.shared.analytics import get_counts

    alerts = [
        {"security_advisory": {"severity": "critical"}},
        {"security_advisory": {"severity": "high"}},
        {"security_advisory": {"severity": "high"}},
        {"security_advisory": {"severity": "medium"}},
        {"security_advisory": {"severity": "low"}},
        {"security_advisory": {"severity": "low"}},
        {"security_advisory": {"severity": "low"}},
    ]

    counts = get_counts(alerts)
    assert counts.total == 7
    assert counts.critical == 1
    assert counts.high == 2
    assert counts.medium == 1
    assert counts.low == 3


def test_dependencies_analytics_severity_distribution():
    from src.shared.analytics import get_severity_distribution

    alerts = [
        {"security_advisory": {"severity": "critical"}},
        {"security_advisory": {"severity": "high"}},
        {"security_advisory": {"severity": "low"}},
    ]

    dist = get_severity_distribution(alerts)
    assert len(dist) == 4
    assert dist[0].severity == "critical"
    assert dist[0].count == 1
    assert dist[0].percentage == 33  # 1/3 rounded


def test_dependencies_analytics_age_buckets():
    from datetime import datetime, timedelta, timezone
    from src.shared.analytics import get_age_buckets

    now = datetime.now(timezone.utc)
    alerts = [
        {"created_at": (now - timedelta(days=3)).isoformat()},  # 0-7d
        {"created_at": (now - timedelta(days=15)).isoformat()},  # 8-30d
        {"created_at": (now - timedelta(days=60)).isoformat()},  # 31-90d
        {"created_at": (now - timedelta(days=100)).isoformat()},  # 90d+
    ]

    buckets = get_age_buckets(alerts)
    assert buckets[0].count == 1
    assert buckets[1].count == 1
    assert buckets[2].count == 1
    assert buckets[3].count == 1


def test_dependencies_analytics_risk_score_calculation():
    from src.shared.analytics import get_risk_score

    # High risk: 50% critical/high
    high_risk_alerts = [
        {"security_advisory": {"severity": "critical"}},
        {"security_advisory": {"severity": "high"}},
        {"security_advisory": {"severity": "low"}},
        {"security_advisory": {"severity": "low"}},
    ]
    score = get_risk_score(high_risk_alerts)
    assert score.score == 50
    assert score.rating == "Moderate"

    # Low risk: all low
    low_risk_alerts = [
        {"security_advisory": {"severity": "low"}},
        {"security_advisory": {"severity": "low"}},
    ]
    score = get_risk_score(low_risk_alerts)
    assert score.score == 0
    assert score.rating == "Low"


def test_dependencies_analytics_remediation_metrics():
    from datetime import datetime, timedelta, timezone
    from src.shared.analytics import get_remediation_metrics

    now = datetime.now(timezone.utc)
    alerts = [
        {"fixed_at": now.isoformat(), "created_at": (now - timedelta(days=5)).isoformat()},
        {"fixed_at": now.isoformat(), "created_at": (now - timedelta(days=15)).isoformat()},
    ]

    metrics = get_remediation_metrics(alerts)
    assert metrics.totalFixed == 2
    assert metrics.avgDays is not None
    assert metrics.fixedLast30d == 2


def test_dependencies_findings_read_returns_empty_list_when_no_data():
    import src.storage as storage

    # read_dependencies_findings returns an empty list when no findings exist for an org
    findings = storage.read_dependencies_findings("nonexistent-org-dependencies-test")
    assert findings == []


def test_dependencies_empty_snapshot_structure():
    from src.storage import empty_dependencies_snapshot

    empty = empty_dependencies_snapshot("Example-Labs")
    assert empty["meta"]["org"] == "example-labs"
    assert empty["alerts"] == []
    assert empty["analytics"]["counts"]["total"] == 0
    assert empty["analytics"]["riskScore"]["score"] == 0


def test_github_client_parse_next_link():
    from src.shared.github import _parse_next_link

    # Test with valid next link
    link_header = '<https://api.github.com/repos/octocat/Hello-World/issues?page=2>; rel="next", <https://api.github.com/repos/octocat/Hello-World/issues?page=5>; rel="last"'
    result = _parse_next_link(link_header)
    assert result == "https://api.github.com/repos/octocat/Hello-World/issues?page=2"

    # Test with no next link
    result = _parse_next_link('<https://api.github.com/repos/octocat/Hello-World/issues?page=1>; rel="last"')
    assert result is None

    # Test with None
    assert _parse_next_link(None) is None


def test_github_client_parse_purl():
    from src.shared.github import _parse_purl

    # Test npm package
    result = _parse_purl("pkg:npm/left-pad@1.3.0")
    assert result == {"ecosystem": "npm", "name": "left-pad"}

    # Test PyPI package (should normalize to pip)
    result = _parse_purl("pkg:pypi/django@4.0")
    assert result == {"ecosystem": "pip", "name": "django"}

    # Test invalid purl
    assert _parse_purl("not-a-purl") is None


