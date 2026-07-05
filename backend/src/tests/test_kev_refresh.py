"""Tests for the KEV refresh job.

Verifies that the job calls fetch + upsert, handles fetch failures by
re-raising, and returns the expected summary dict on success.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestRefreshKevCatalog:
    @patch("src.kev.fetcher.httpx.Client")
    def test_calls_fetcher_and_service(self, mock_http_client_cls):
        """Job fetches catalog, upserts via service, returns summary dict."""
        from src.jobs.kev_refresh import refresh_kev_catalog

        payload = {"vulnerabilities": [{"cveID": "CVE-2024-99999", "vendorProject": "Test"}]}
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = payload
        mock_http_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        # Mock the service so we don't need a real DB connection. upsert_catalog
        # returns the list of newly-added CVE IDs, so the mock returns a list.
        with patch("src.kev.service.run_db", return_value=["CVE-2024-99999"]):
            result = refresh_kev_catalog()

        assert result["fetched"] == 1
        assert result["new"] == 1

    @patch("src.kev.fetcher.httpx.Client")
    def test_fetch_failure_propagates(self, mock_http_client_cls):
        """Network failures are NOT swallowed — they propagate to the caller."""
        import httpx
        from src.jobs.kev_refresh import refresh_kev_catalog

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "503", request=MagicMock(), response=MagicMock()
        )
        mock_http_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        with pytest.raises(httpx.HTTPStatusError):
            refresh_kev_catalog()

    @patch("src.kev.fetcher.httpx.Client")
    def test_returns_zero_new_on_repeat_run(self, mock_http_client_cls):
        """If catalog hasn't changed, new count is 0."""
        from src.jobs.kev_refresh import refresh_kev_catalog

        payload = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-11111"},
                {"cveID": "CVE-2024-22222"},
            ]
        }
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = payload
        mock_http_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        with patch("src.kev.service.run_db", return_value=[]):
            result = refresh_kev_catalog()

        assert result["fetched"] == 2
        assert result["new"] == 0

    @patch("src.kev.fetcher.httpx.Client")
    def test_empty_catalog_handled(self, mock_http_client_cls):
        """Empty feed (e.g., during maintenance) returns fetched=0, new=0."""
        from src.jobs.kev_refresh import refresh_kev_catalog

        payload = {"vulnerabilities": []}
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = payload
        mock_http_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        with patch("src.kev.service.run_db", return_value=[]):
            result = refresh_kev_catalog()

        assert result["fetched"] == 0
        assert result["new"] == 0
