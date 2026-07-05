"""Verify each legacy URL from next.config.ts redirects() lands on the new home."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.auth.authentication.redirects import LegacyRedirectMiddleware

REDIRECT_CASES = [
    ("/settings/sources/code-repositories", "/sources/code-repositories"),
    ("/settings/sources/code-repositories/abc-123", "/sources/code-repositories/abc-123"),
    ("/settings/sources/container-images", "/sources/container-registry"),
    ("/settings/sources/container-images/def-456", "/sources/container-registry/def-456"),
    ("/settings/sources/ci-cd-pipelines", "/sources/code-repositories"),
    ("/settings/sources/ci-cd-pipelines/x/y/z", "/sources/code-repositories"),

    # Trailing-slash variants — Next.js used /?$ optional slash too
    ("/settings/sources/code-repositories/", "/sources/code-repositories"),

    # Query string on the :id variant — destination keeps the id, drops the query
    ("/settings/sources/code-repositories/abc?ref=link", "/sources/code-repositories/abc"),

    # ci-cd-pipelines with query string — sub-path AND query both dropped (matches Next.js)
    ("/settings/sources/ci-cd-pipelines/foo/bar?ref=x", "/sources/code-repositories"),
]


@pytest.fixture
def app_with_redirects():
    app = FastAPI()
    app.add_middleware(LegacyRedirectMiddleware)

    @app.get("/")
    def home():
        return {"ok": True}

    return app


@pytest.mark.parametrize("source,expected_location", REDIRECT_CASES)
def test_legacy_url_redirects(app_with_redirects, source, expected_location):
    client = TestClient(app_with_redirects, follow_redirects=False)
    response = client.get(source)
    assert response.status_code in (301, 308)  # permanent redirect
    assert response.headers["location"] == expected_location


def test_non_legacy_url_passes_through(app_with_redirects):
    client = TestClient(app_with_redirects)
    response = client.get("/")
    assert response.status_code == 200
