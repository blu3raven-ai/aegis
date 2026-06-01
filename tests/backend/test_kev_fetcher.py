"""Tests for the CISA KEV catalog fetcher.

Uses a golden-fixture JSON file (tests/backend/fixtures/kev_sample.json) so
parser tests are fully offline — no network calls in CI.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.kev.fetcher import (
    CISA_KEV_JSON_URL,
    _normalise_entry,
    _parse_date,
    _parse_ransomware,
    fetch_kev_catalog,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Unit helpers
# ---------------------------------------------------------------------------

class TestParseDateHelper:
    def test_valid_iso(self):
        from datetime import date
        assert _parse_date("2024-01-15") == date(2024, 1, 15)

    def test_none_returns_none(self):
        assert _parse_date(None) is None

    def test_empty_returns_none(self):
        assert _parse_date("") is None

    def test_invalid_returns_none(self):
        assert _parse_date("not-a-date") is None

    def test_leading_trailing_whitespace(self):
        from datetime import date
        assert _parse_date("  2024-06-01  ") == date(2024, 6, 1)


class TestParseRansomwareHelper:
    def test_known(self):
        assert _parse_ransomware("Known") is True

    def test_unknown(self):
        assert _parse_ransomware("Unknown") is False

    def test_empty_returns_none(self):
        assert _parse_ransomware("") is None

    def test_none_returns_none(self):
        assert _parse_ransomware(None) is None

    def test_case_insensitive(self):
        assert _parse_ransomware("known") is True
        assert _parse_ransomware("UNKNOWN") is False


class TestNormaliseEntry:
    def test_full_entry(self):
        raw = {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 RCE",
            "dateAdded": "2021-12-10",
            "shortDescription": "JNDI RCE",
            "requiredAction": "Apply updates.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-20"],
        }
        entry = _normalise_entry(raw)
        assert entry is not None
        assert entry["cve_id"] == "CVE-2021-44228"
        assert entry["vendor_project"] == "Apache"
        assert entry["known_ransomware_use"] is True

    def test_missing_cve_id_returns_none(self):
        raw = {"vendorProject": "Apache", "product": "Log4j2"}
        assert _normalise_entry(raw) is None

    def test_missing_optional_fields_default_none(self):
        raw = {"cveID": "CVE-2024-99999"}
        entry = _normalise_entry(raw)
        assert entry is not None
        assert entry["vendor_project"] is None
        assert entry["due_date"] is None
        assert entry["known_ransomware_use"] is None


# ---------------------------------------------------------------------------
# Golden fixture parse
# ---------------------------------------------------------------------------

class TestGoldenFixture:
    def _load_fixture_payload(self) -> dict:
        with open(FIXTURES_DIR / "kev_sample.json") as f:
            return json.load(f)

    def test_parse_all_entries(self):
        payload = self._load_fixture_payload()
        raw_entries = payload["vulnerabilities"]
        entries = []
        for raw in raw_entries:
            entry = _normalise_entry(raw)
            if entry:
                entries.append(entry)

        assert len(entries) == 5

    def test_log4j_entry(self):
        payload = self._load_fixture_payload()
        raw = next(v for v in payload["vulnerabilities"] if v["cveID"] == "CVE-2021-44228")
        entry = _normalise_entry(raw)
        assert entry["cve_id"] == "CVE-2021-44228"
        assert entry["vendor_project"] == "Apache"
        assert entry["known_ransomware_use"] is True
        assert isinstance(entry["cwes"], list)
        assert "CWE-20" in entry["cwes"]

    def test_ransomware_unknown_maps_to_false(self):
        payload = self._load_fixture_payload()
        raw = next(v for v in payload["vulnerabilities"] if v["cveID"] == "CVE-2024-21762")
        entry = _normalise_entry(raw)
        assert entry["known_ransomware_use"] is False


# ---------------------------------------------------------------------------
# fetch_kev_catalog (mocked HTTP)
# ---------------------------------------------------------------------------

class TestFetchKevCatalog:
    def _make_response(self, payload: dict, status_code: int = 200):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = payload
        resp.raise_for_status.return_value = None
        return resp

    def _fixture_payload(self) -> dict:
        with open(FIXTURES_DIR / "kev_sample.json") as f:
            return json.load(f)

    @patch("src.kev.fetcher.httpx.Client")
    def test_returns_parsed_entries(self, mock_client_cls):
        payload = self._fixture_payload()
        mock_resp = self._make_response(payload)
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        entries = fetch_kev_catalog()
        assert len(entries) == 5
        assert all("cve_id" in e for e in entries)

    @patch("src.kev.fetcher.httpx.Client")
    def test_http_error_propagates(self, mock_client_cls):
        import httpx
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404", request=MagicMock(), response=MagicMock()
        )
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        with pytest.raises(httpx.HTTPStatusError):
            fetch_kev_catalog()

    @patch("src.kev.fetcher.httpx.Client")
    def test_skips_entries_without_cve_id(self, mock_client_cls):
        """Rows missing cveID are skipped; valid rows still return."""
        payload = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-99999", "vendorProject": "Test"},
                {"vendorProject": "Missing CVE ID"},  # should be skipped
                {"cveID": "CVE-2024-11111"},
            ]
        }
        mock_resp = self._make_response(payload)
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        entries = fetch_kev_catalog()
        assert len(entries) == 2
        assert entries[0]["cve_id"] == "CVE-2024-99999"

    @patch("src.kev.fetcher.httpx.Client")
    def test_unexpected_feed_shape_raises(self, mock_client_cls):
        """If the feed returns a non-list under 'vulnerabilities', raise ValueError."""
        payload = {"vulnerabilities": "not a list"}
        mock_resp = self._make_response(payload)
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        with pytest.raises(ValueError, match="Unexpected CISA KEV feed shape"):
            fetch_kev_catalog()

    @patch("src.kev.fetcher.httpx.Client")
    def test_malformed_row_skipped_not_raised(self, mock_client_cls):
        """A row that raises during normalise is logged and skipped."""
        payload = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-99999"},
                None,  # will raise AttributeError in _normalise_entry
                {"cveID": "CVE-2024-11111"},
            ]
        }
        mock_resp = self._make_response(payload)
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        # Should not raise — malformed row is skipped
        entries = fetch_kev_catalog()
        assert len(entries) == 2
