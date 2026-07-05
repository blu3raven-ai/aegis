"""Tests for [classify] N/M progress line parsing."""
from src.secrets.scanner import (
    extract_repo_progress,
    observe_scan_progress_line,
    ScanProgressState,
    summarize_scan_progress,
    parse_progress_from_lines,
)
from src.secrets.store import default_secret_run_progress


def test_extract_repo_progress_classify_line():
    result = extract_repo_progress("  [classify] 14/2092")
    assert result == {"type": "classifying", "progress": "14/2092"}


def test_extract_repo_progress_classify_line_no_leading_space():
    result = extract_repo_progress("[classify] 1/50")
    assert result == {"type": "classifying", "progress": "1/50"}


def test_observe_classify_line_sets_stage_and_progress():
    state = ScanProgressState(stage="scanning")
    observe_scan_progress_line(state, "[classify] 7/100")
    assert state.stage == "classifying"
    assert state.current_classifying == "7/100"


def test_observe_ingesting_clears_classifying():
    state = ScanProgressState(stage="classifying")
    state.current_classifying = "100/100"
    observe_scan_progress_line(state, "Normalizing results for organization example-org")
    assert state.stage == "ingesting"
    assert state.current_classifying is None


def test_summarize_scan_progress_includes_current_classifying():
    state = ScanProgressState(stage="classifying")
    state.current_classifying = "42/500"
    fallback = default_secret_run_progress()
    result = summarize_scan_progress(state, fallback)
    assert result["currentClassifying"] == "42/500"
    assert result["stage"] == "classifying"


def test_summarize_scan_progress_classifying_none_when_not_set():
    state = ScanProgressState(stage="scanning")
    fallback = default_secret_run_progress()
    result = summarize_scan_progress(state, fallback)
    assert result["currentClassifying"] is None


def test_default_secret_run_progress_has_current_classifying():
    progress = default_secret_run_progress()
    assert "currentClassifying" in progress
    assert progress["currentClassifying"] is None


def test_parse_progress_from_lines_classifying():
    lines = [
        "[+] Scanning repo: example-org/repo-a",
        "[✓] Finished example-org/repo-a — 0 finding file(s) in 2s",
        "[classify] 50/200",
        "[classify] 100/200",
    ]
    fallback = default_secret_run_progress()
    result = parse_progress_from_lines(lines, fallback)
    assert result["stage"] == "classifying"
    assert result["currentClassifying"] == "100/200"


def test_parse_progress_from_lines_classifying_cleared_by_ingesting():
    lines = [
        "[classify] 200/200",
        "Normalizing results for organization example-org",
    ]
    fallback = default_secret_run_progress()
    result = parse_progress_from_lines(lines, fallback)
    assert result["stage"] == "ingesting"
    assert result["currentClassifying"] is None
