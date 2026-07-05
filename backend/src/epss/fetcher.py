"""FIRST.org EPSS scores fetcher.

Downloads the daily gzipped CSV from FIRST.org, decompresses it, parses each
row, and returns a list ready for upsert. Network I/O only ever touches
epss.cyentia.com — no third-party intel proxies.

The feed format is:
    #model_version:vYYYY.MM.DD,score_date:YYYY-MM-DDT00:00:00+0000
    cve,epss,percentile
    CVE-2024-1234,0.97123,0.99876
    ...
"""
from __future__ import annotations

import csv
import gzip
import io
import logging
import re
from datetime import date
from typing import Any

import httpx

logger = logging.getLogger(__name__)

EPSS_CSV_GZ_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

_SCORE_DATE_RE = re.compile(r"score_date:(\d{4}-\d{2}-\d{2})")


def _parse_score_date(header_line: str) -> date | None:
    """Extract the score_date from the EPSS CSV header comment line."""
    if not header_line:
        return None
    match = _SCORE_DATE_RE.search(header_line)
    if not match:
        return None
    try:
        return date.fromisoformat(match.group(1))
    except ValueError:
        return None


def _parse_float(raw: str | None) -> float | None:
    """Parse a probability string from the CSV; return None on any failure."""
    if raw is None:
        return None
    try:
        return float(raw.strip())
    except (ValueError, AttributeError):
        return None


def _normalise_row(raw: dict[str, str], scored_date: date) -> dict[str, Any] | None:
    """Map one CSV row to our internal field names.

    Returns None when the row has no cve, an invalid score, or a percentile
    outside the [0, 1] range — these are the fields we need to be well-formed
    for downstream prioritisation queries.
    """
    cve = (raw.get("cve") or "").strip()
    if not cve:
        return None

    score = _parse_float(raw.get("epss"))
    percentile = _parse_float(raw.get("percentile"))
    if score is None or percentile is None:
        return None
    if not (0.0 <= score <= 1.0) or not (0.0 <= percentile <= 1.0):
        return None

    return {
        "cve": cve.upper(),
        "score": score,
        "percentile": percentile,
        "scored_date": scored_date,
    }


def _parse_csv_bytes(data: bytes) -> list[dict[str, Any]]:
    """Parse a decompressed EPSS CSV blob into normalised rows.

    The first line is a comment with the score_date; subsequent lines are
    a standard CSV with header `cve,epss,percentile`.
    """
    text = data.decode("utf-8", errors="replace")
    buf = io.StringIO(text)

    first_line = buf.readline().strip()
    scored_date = _parse_score_date(first_line) or date.today()

    reader = csv.DictReader(buf)
    if reader.fieldnames is None or "cve" not in reader.fieldnames:
        raise ValueError(
            f"Unexpected EPSS CSV shape: header is {reader.fieldnames!r}"
        )

    rows: list[dict[str, Any]] = []
    for i, raw in enumerate(reader):
        try:
            entry = _normalise_row(raw, scored_date)
            if entry is None:
                logger.warning("EPSS row %d malformed — skipping: %r", i, raw)
                continue
            rows.append(entry)
        except Exception:
            logger.warning("Failed to parse EPSS row %d — skipping: %r", i, raw, exc_info=True)

    return rows


def fetch_epss_scores(timeout: float = 60.0) -> list[dict[str, Any]]:
    """Fetch and parse the current EPSS scores feed from FIRST.org.

    Returns a list of normalised row dicts ready for EpssService.upsert_scores.
    Raises httpx.HTTPError on network failures so callers can decide on retry
    strategy without swallowing transport errors silently.

    Individual rows that cannot be parsed are skipped with a WARNING log so a
    single malformed row never aborts the full refresh.
    """
    with httpx.Client(timeout=timeout) as client:
        resp = client.get(EPSS_CSV_GZ_URL)
        resp.raise_for_status()
        compressed = resp.content

    try:
        decompressed = gzip.decompress(compressed)
    except OSError as exc:
        raise ValueError("EPSS feed is not valid gzip") from exc

    rows = _parse_csv_bytes(decompressed)
    logger.info("Fetched %d EPSS rows from FIRST.org", len(rows))
    return rows
