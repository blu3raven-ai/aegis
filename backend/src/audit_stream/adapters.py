"""Audit-stream delivery adapters: generic webhook, Splunk HEC, syslog TCP."""
from __future__ import annotations

import asyncio
import json
import socket
import uuid

import httpx

from src.db.models import AuditStreamConfig
from src.security.crypto import decrypt


def _token_for(cfg: AuditStreamConfig) -> str | None:
    return decrypt(cfg.auth_token_enc) if cfg.auth_token_enc else None


async def webhook_deliver(
    url: str,
    token: str | None,
    events: list[dict],
    transport: httpx.BaseTransport | None = None,
) -> dict:
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=10.0, transport=transport) as client:
            resp = await client.post(url, json={"events": events}, headers=headers)
            if resp.status_code >= 300:
                return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}
    return {"ok": True, "error": None}


async def splunk_hec_deliver(
    url: str,
    token: str | None,
    events: list[dict],
    transport: httpx.BaseTransport | None = None,
) -> dict:
    headers: dict[str, str] = {
        "Authorization": f"Splunk {token or ''}",
        "X-Splunk-Request-Channel": str(uuid.uuid4()),
    }
    full_url = url.rstrip("/") + "/services/collector/raw"
    body = "\n".join(json.dumps(e) for e in events)
    try:
        async with httpx.AsyncClient(timeout=10.0, transport=transport) as client:
            resp = await client.post(full_url, content=body.encode(), headers=headers)
            if resp.status_code >= 300:
                return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}
    return {"ok": True, "error": None}


async def syslog_deliver(
    url: str,
    token: str | None,
    events: list[dict],
) -> dict:
    host, _, port_s = url.partition(":")
    if not host or not port_s.isdigit():
        return {"ok": False, "error": "Syslog target must be 'host:port'."}
    port = int(port_s)
    try:
        await asyncio.get_running_loop().run_in_executor(None, _syslog_write, host, port, events)
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}
    return {"ok": True, "error": None}


def _syslog_write(host: str, port: int, events: list[dict]) -> None:
    with socket.create_connection((host, port), timeout=10.0) as sock:
        for e in events:
            line = (
                f"<134>1 {e.get('timestamp', '-')} aegis aegis-audit - - - "
                + json.dumps(e)
                + "\n"
            )
            sock.sendall(line.encode("utf-8"))


async def deliver_test_event(cfg: AuditStreamConfig) -> dict:
    if not cfg.target_type or not cfg.endpoint_url:
        return {"ok": False, "error": "Target type and endpoint URL are required."}
    test_event = {
        "id": 0,
        "timestamp": "2026-06-08T00:00:00Z",
        "action": "audit_stream.test",
        "actor": {"id": "system", "email": "audit-stream-test@aegis.local"},
    }
    token = _token_for(cfg)
    if cfg.target_type == "webhook":
        return await webhook_deliver(cfg.endpoint_url, token, [test_event])
    if cfg.target_type == "splunk_hec":
        return await splunk_hec_deliver(cfg.endpoint_url, token, [test_event])
    if cfg.target_type == "syslog":
        return await syslog_deliver(cfg.endpoint_url, token, [test_event])
    return {"ok": False, "error": f"Unknown target_type: {cfg.target_type}"}
