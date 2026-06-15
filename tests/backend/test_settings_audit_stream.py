def test_get_audit_stream_returns_defaults(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="audit-stream-1")
    resp = client.get("/api/v1/settings/audit-stream")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["enabled"] is False
    assert body["targetType"] is None
    assert body["authTokenSet"] is False
    assert body["lastEventId"] == 0


def test_patch_audit_stream_sets_target(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from conftest import make_authed_client
    client = make_authed_client(role="admin", user_id="audit-stream-2")
    resp = client.patch("/api/v1/settings/audit-stream", json={
        "targetType": "webhook",
        "endpointUrl": "https://hooks.example.com/aegis",
        "authToken": "sekret-99",
        "enabled": True,
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["enabled"] is True
    assert body["targetType"] == "webhook"
    assert body["endpointUrl"] == "https://hooks.example.com/aegis"
    assert body["authTokenSet"] is True


def test_patch_audit_stream_requires_manage_settings(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from conftest import make_authed_client
    client = make_authed_client(role="viewer", user_id="audit-stream-3")
    resp = client.patch("/api/v1/settings/audit-stream", json={"enabled": True})
    assert resp.status_code == 403
