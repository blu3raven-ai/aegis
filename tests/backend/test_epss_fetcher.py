"""Tests for the EPSS scores fetcher.

Uses a golden-fixture gzipped CSV (tests/backend/fixtures/epss_sample.csv.gz)
so parser tests are fully offline — no network calls in CI.
"""
from __future__ import annotations

import gzip
from datetime import date
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.epss.fetcher import (
    EPSS_CSV_GZ_URL,
    _normalise_row,
    _parse_csv_bytes,
    _parse_float,
    _parse_score_date,
    fetch_epss_scores,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Unit helpers
# ---------------------------------------------------------------------------


class TestParseScoreDate:
    def test_valid_header(self):
        header = "#model_version:v2024.04.25,score_date:2024-05-13T00:00:00+0000"
        assert _parse_score_date(header) == date(2024, 5, 13)

    def test_no_match_returns_none(self):
        assert _parse_score_date("#nothing here") is None

    def test_empty_returns_none(self):
        assert _parse_score_date("") is None

    def test_malformed_date_returns_none(self):
        assert _parse_score_date("#score_date:not-a-date") is None


class TestParseFloat:
    def test_valid(self):
        assert _parse_float("0.5") == 0.5

    def test_whitespace(self):
        assert _parse_float("  0.1  ") == 0.1

    def test_none(self):
        assert _parse_float(None) is None

    def test_invalid(self):
        assert _parse_float("not-a-number") is None


class TestNormaliseRow:
    def test_valid_row(self):
        row = {"cve": "CVE-2024-1234", "epss": "0.95", "percentile": "0.99"}
        entry = _normalise_row(row, date(2024, 5, 13))
        assert entry is not None
        assert entry["cve"] == "CVE-2024-1234"
        assert entry["score"] == 0.95
        assert entry["percentile"] == 0.99
        assert entry["scored_date"] == date(2024, 5, 13)

    def test_lowercase_cve_uppercased(self):
        row = {"cve": "cve-2024-1234", "epss": "0.1", "percentile": "0.2"}
        entry = _normalise_row(row, date(2024, 5, 13))
        assert entry["cve"] == "CVE-2024-1234"

    def test_missing_cve_returns_none(self):
        row = {"cve": "", "epss": "0.1", "percentile": "0.2"}
        assert _normalise_row(row, date(2024, 5, 13)) is None

    def test_missing_score_returns_none(self):
        row = {"cve": "CVE-2024-1234", "epss": "", "percentile": "0.2"}
        assert _normalise_row(row, date(2024, 5, 13)) is None

    def test_out_of_range_score_returns_none(self):
        row = {"cve": "CVE-2024-1234", "epss": "1.5", "percentile": "0.2"}
        assert _normalise_row(row, date(2024, 5, 13)) is None

    def test_negative_percentile_returns_none(self):
        row = {"cve": "CVE-2024-1234", "epss": "0.1", "percentile": "-0.1"}
        assert _normalise_row(row, date(2024, 5, 13)) is None


# ---------------------------------------------------------------------------
# CSV bytes parsing
# ---------------------------------------------------------------------------


class TestParseCsvBytes:
    def _csv_bytes(self) -> bytes:
        return (
            "#model_version:v2024.04.25,score_date:2024-05-13T00:00:00+0000\n"
            "cve,epss,percentile\n"
            "CVE-2024-1234,0.95,0.99\n"
            "CVE-2024-5678,0.10,0.50\n"
        ).encode("utf-8")

    def test_parses_two_rows(self):
        rows = _parse_csv_bytes(self._csv_bytes())
        assert len(rows) == 2
        assert rows[0]["cve"] == "CVE-2024-1234"
        assert rows[0]["scored_date"] == date(2024, 5, 13)

    def test_unexpected_header_raises(self):
        data = b"#model_version:v1\nfoo,bar\n1,2\n"
        with pytest.raises(ValueError, match="Unexpected EPSS CSV shape"):
            _parse_csv_bytes(data)

    def test_malformed_rows_skipped(self):
        data = (
            "#score_date:2024-05-13T00:00:00+0000\n"
            "cve,epss,percentile\n"
            "CVE-2024-1234,0.95,0.99\n"
            ",0.5,0.5\n"
            "CVE-2024-9999,nan-not,0.5\n"
            "CVE-2024-0001,0.1,0.2\n"
        ).encode("utf-8")
        rows = _parse_csv_bytes(data)
        assert len(rows) == 2
        assert {r["cve"] for r in rows} == {"CVE-2024-1234", "CVE-2024-0001"}


# ---------------------------------------------------------------------------
# Golden fixture parse
# ---------------------------------------------------------------------------


class TestGoldenFixture:
    def _load(self) -> bytes:
        with open(FIXTURES_DIR / "epss_sample.csv.gz", "rb") as f:
            return gzip.decompress(f.read())

    def test_parse_all_rows(self):
        rows = _parse_csv_bytes(self._load())
        assert len(rows) == 5

    def test_log4j_score(self):
        rows = _parse_csv_bytes(self._load())
        log4j = next(r for r in rows if r["cve"] == "CVE-2021-44228")
        assert log4j["score"] == pytest.approx(0.97412)
        assert log4j["percentile"] == pytest.approx(0.99987)

    def test_scored_date_extracted(self):
        rows = _parse_csv_bytes(self._load())
        for r in rows:
            assert r["scored_date"] == date(2024, 5, 13)


# ---------------------------------------------------------------------------
# fetch_epss_scores (mocked HTTP)
# ---------------------------------------------------------------------------


class TestFetchEpssScores:
    def _fixture_gz(self) -> bytes:
        with open(FIXTURES_DIR / "epss_sample.csv.gz", "rb") as f:
            return f.read()

    def _make_response(self, content: bytes, status_code: int = 200):
        resp = MagicMock()
        resp.status_code = status_code
        resp.content = content
        resp.raise_for_status.return_value = None
        return resp

    @patch("src.epss.fetcher.httpx.Client")
    def test_returns_parsed_rows(self, mock_client_cls):
        resp = self._make_response(self._fixture_gz())
        mock_client_cls.return_value.__enter__.return_value.get.return_value = resp
        rows = fetch_epss_scores()
        assert len(rows) == 5
        assert all("cve" in r and "score" in r for r in rows)

    @patch("src.epss.fetcher.httpx.Client")
    def test_http_error_propagates(self, mock_client_cls):
        import httpx
        resp = MagicMock()
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "503", request=MagicMock(), response=MagicMock()
        )
        mock_client_cls.return_value.__enter__.return_value.get.return_value = resp
        with pytest.raises(httpx.HTTPStatusError):
            fetch_epss_scores()

    @patch("src.epss.fetcher.httpx.Client")
    def test_non_gzip_body_raises(self, mock_client_cls):
        resp = self._make_response(b"not gzipped bytes")
        mock_client_cls.return_value.__enter__.return_value.get.return_value = resp
        with pytest.raises(ValueError, match="not valid gzip"):
            fetch_epss_scores()

    def test_known_url(self):
        assert EPSS_CSV_GZ_URL == "https://epss.cyentia.com/epss_scores-current.csv.gz"
