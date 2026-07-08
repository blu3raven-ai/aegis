"""The secrets code window must never leak any detected raw secret value."""
from __future__ import annotations

import json

from runner.scanners.secrets.normalize import capture_secret_windows, normalize_file


def test_secret_code_window_redacts_every_value(tmp_path):
    repo = tmp_path / "myrepo"
    checkout = repo / "_checkout"
    (checkout / "config").mkdir(parents=True)

    secret_a = "AKIAIOSFODNN7EXAMPLE"
    secret_b = "sk-livesupersecrettoken9999"
    env = checkout / "config" / ".env"
    env.write_text(f"AWS_KEY={secret_a}\nOPENAI={secret_b}\nDEBUG=true\n")

    out = repo / "out.json"
    out.write_text("\n".join([
        json.dumps({
            "Raw": secret_a, "Redacted": "AKIA...MPLE", "DetectorName": "AWS",
            "SourceMetadata": {"Data": {"Filesystem": {"file": str(env), "line": 1}}},
        }),
        json.dumps({
            "Raw": secret_b, "Redacted": "sk-...9999", "DetectorName": "OpenAI",
            "SourceMetadata": {"Data": {"Filesystem": {"file": str(env), "line": 2}}},
        }),
    ]))

    # The window is captured while the clone still exists; normalization then
    # reads the persisted window (the clone is gone by then in the real flow).
    capture_secret_windows(out, checkout)

    findings = normalize_file(out, "trufflehog", "myrepo")
    assert len(findings) == 2
    for finding in findings:
        window = finding.get("code_window")
        assert window is not None, "expected a runner-extracted code window"
        # BOTH detected secrets masked in EVERY window — not just the finding's own.
        assert secret_a not in window
        assert secret_b not in window
        # TruffleHog's own Redacted form (a genuine partial) is shown so an
        # analyst can identify the secret without seeing the full value.
        assert "AKIA...MPLE" in window
        assert "sk-...9999" in window
        # surrounding non-secret context is preserved.
        assert "DEBUG=true" in window


def test_secret_window_skipped_when_source_unreadable(tmp_path):
    """No clone -> no window (falls back to the redacted match), never raises."""
    repo = tmp_path / "r"
    repo.mkdir()
    out = repo / "out.json"
    out.write_text(json.dumps({
        "Raw": "x", "Redacted": "x", "DetectorName": "AWS",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env", "line": 1}}},
    }))
    capture_secret_windows(out, repo / "_checkout")  # clone never existed
    findings = normalize_file(out, "trufflehog", "r")
    assert len(findings) == 1
    assert findings[0].get("code_window") is None


def _secret_scan_output(path):
    path.write_text(json.dumps({
        "Raw": "x", "Redacted": "x", "DetectorName": "AWS",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "a.env", "line": 1}}},
    }))


def test_normalize_stamps_repo_html_url_from_sidecar(tmp_path):
    repo = tmp_path / "myrepo"
    repo.mkdir()
    (repo / "html_url.txt").write_text("https://ghe.acme-corp.internal/acme/myrepo\n")
    out = repo / "out.json"
    _secret_scan_output(out)
    findings = normalize_file(out, "trufflehog", "myrepo")
    assert findings[0]["repo_html_url"] == "https://ghe.acme-corp.internal/acme/myrepo"


def test_normalize_omits_repo_html_url_when_no_sidecar(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    out = repo / "out.json"
    _secret_scan_output(out)
    findings = normalize_file(out, "trufflehog", "r")
    assert "repo_html_url" not in findings[0]
