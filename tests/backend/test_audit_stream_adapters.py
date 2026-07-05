import asyncio


def test_webhook_success(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    import httpx
    from src.audit_stream.adapters import webhook_deliver

    transport = httpx.MockTransport(lambda req: httpx.Response(200))
    result = asyncio.run(webhook_deliver(
        url="https://hook.example.com/x",
        token="bearer-x",
        events=[{"id": 1, "timestamp": "2026-06-08T00:00:00Z", "action": "test"}],
        transport=transport,
    ))
    assert result == {"ok": True, "error": None}


def test_webhook_failure_returns_error(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    import httpx
    from src.audit_stream.adapters import webhook_deliver

    transport = httpx.MockTransport(lambda req: httpx.Response(500, text="boom"))
    result = asyncio.run(webhook_deliver(
        url="https://hook.example.com/x",
        token=None,
        events=[{"id": 1}],
        transport=transport,
    ))
    assert result["ok"] is False
    assert "500" in result["error"] or "boom" in result["error"].lower()


def test_splunk_hec_uses_correct_headers(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    import httpx
    from src.audit_stream.adapters import splunk_hec_deliver

    captured = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["url"] = str(req.url)
        captured["auth"] = req.headers.get("authorization")
        captured["channel"] = req.headers.get("x-splunk-request-channel")
        captured["body"] = req.content.decode()
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    result = asyncio.run(splunk_hec_deliver(
        url="https://splunk.example.com:8088",
        token="HEC-TOKEN-123",
        events=[{"id": 1, "action": "test"}],
        transport=transport,
    ))
    assert result["ok"] is True
    assert captured["url"].endswith("/services/collector/raw")
    assert captured["auth"] == "Splunk HEC-TOKEN-123"
    assert captured["channel"]
