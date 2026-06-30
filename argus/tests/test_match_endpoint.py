"""Round-trip tests for the Argus /v1/match endpoint (matcher stubbed)."""
from __future__ import annotations

import argus.service as service
from argus.models import MatchAdvisory, MatchItem, MatchPackage
from fastapi.testclient import TestClient

client = TestClient(service.app)

_BODY = {
    "surface": "deps",
    "components": [{"purl": "pkg:pypi/django@4.2.0", "version": "4.2.0"}],
}


def test_match_requires_bearer() -> None:
    resp = client.post("/v1/match", json=_BODY)
    assert resp.status_code in (401, 403)


def test_match_empty_by_default() -> None:
    resp = client.post(
        "/v1/match", json=_BODY, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    assert resp.json() == {"matches": []}


def test_match_round_trips_a_hit(monkeypatch) -> None:
    item = MatchItem(
        package=MatchPackage(name="django", ecosystem="PyPI"),
        version="4.2.0",
        manifest_path="requirements.txt",
        advisory=MatchAdvisory(
            id="GHSA-xxxx",
            cve_id="CVE-2024-1",
            severity="high",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L",
            summary="bad",
            description="really bad",
            html_url="https://example.test/a",
            references=[{"url": "https://example.test/r"}],
            published_at="2024-01-01T00:00:00Z",
            vulnerable_version_range="< 4.2.1",
            first_patched_version="4.2.1",
        ),
    )
    monkeypatch.setattr(
        service, "match_components", lambda surface, components, **kwargs: [item]
    )

    resp = client.post(
        "/v1/match", json=_BODY, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    matches = resp.json()["matches"]
    assert len(matches) == 1
    hit = matches[0]
    assert hit["package"]["name"] == "django"
    assert hit["version"] == "4.2.0"
    assert hit["advisory"]["id"] == "GHSA-xxxx"


def test_match_rejects_malformed_body() -> None:
    resp = client.post(
        "/v1/match",
        json={"surface": "deps"},
        headers={"Authorization": "Bearer test-token"},
    )
    assert resp.status_code == 422
