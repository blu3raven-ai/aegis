"""Tests for the EPSS refresh job.

Verifies that the job calls fetch + upsert, handles fetch failures by
re-raising, and returns the expected summary dict on success.
"""
from __future__ import annotations

import gzip
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _fixture_gz() -> bytes:
    with open(FIXTURES_DIR / "epss_sample.csv.gz", "rb") as f:
        return f.read()


class TestRefreshEpssScores:
    @patch("src.epss.fetcher.httpx.Client")
    def test_calls_fetcher_and_service(self, mock_http_client_cls):
        """Job fetches feed, upserts via service, returns summary dict."""
        from src.jobs.epss_refresh import refresh_epss_scores

        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.content = _fixture_gz()
        mock_http_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        with patch("src.epss.service.run_db", return_value=5):
            result = refresh_epss_scores()

        assert result["fetched"] == 5
        assert result["new"] == 5

    @patch("src.epss.fetcher.httpx.Client")
    def test_fetch_failure_propagates(self, mock_http_client_cls):
        """Network failures are NOT swallowed — they propagate to the caller."""
        import httpx
        from src.jobs.epss_refresh import refresh_epss_scores

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "503", request=MagicMock(), response=MagicMock()
        )
        mock_http_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        with pytest.raises(httpx.HTTPStatusError):
            refresh_epss_scores()

    @patch("src.epss.fetcher.httpx.Client")
    def test_returns_zero_new_on_repeat_run(self, mock_http_client_cls):
        """If feed hasn't changed, new count is 0."""
        from src.jobs.epss_refresh import refresh_epss_scores

        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.content = _fixture_gz()
        mock_http_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        with patch("src.epss.service.run_db", return_value=0):
            result = refresh_epss_scores()

        assert result["fetched"] == 5
        assert result["new"] == 0

    @patch("src.epss.fetcher.httpx.Client")
    def test_non_gzip_body_raises(self, mock_http_client_cls):
        """A non-gzip body raises ValueError without touching the service."""
        from src.jobs.epss_refresh import refresh_epss_scores

        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.content = b"not gzipped"
        mock_http_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        with pytest.raises(ValueError, match="not valid gzip"):
            refresh_epss_scores()

    @patch("src.epss.fetcher.httpx.Client")
    def test_empty_feed_handled(self, mock_http_client_cls):
        """Empty feed returns fetched=0, new=0."""
        from src.jobs.epss_refresh import refresh_epss_scores

        empty_csv = b"#score_date:2024-05-13T00:00:00+0000\ncve,epss,percentile\n"
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.content = gzip.compress(empty_csv)
        mock_http_client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        with patch("src.epss.service.run_db", return_value=0):
            result = refresh_epss_scores()

        assert result["fetched"] == 0
        assert result["new"] == 0
