# aegis-webhooks (Python)

Verify [Aegis](https://github.com/blu3raven-ai/aegis) webhook signatures — HMAC-SHA256 with replay protection.

## Install

```bash
pip install aegis-webhooks
```

## Quickstart

```python
from aegis_webhooks import verify_signature, AegisWebhookError

WEBHOOK_SECRET = "your-signing-secret"  # from Aegis notification settings

@app.post("/webhook")
def receive_webhook():
    try:
        verify_signature(
            request.data,          # raw bytes
            WEBHOOK_SECRET,
            request.headers,
        )
    except AegisWebhookError as exc:
        return {"error": str(exc)}, 400

    event = request.get_json()
    # ... handle event
```

## Rotation

Pass a list of secrets to accept either key during a rotation window:

```python
verify_signature(payload, [old_secret, new_secret], headers)
```

## API

```python
verify_signature(
    payload,             # dict | bytes | str
    secret,              # str | list[str]
    headers,             # any Mapping[str, str] — case-insensitive lookup
    *,
    tolerance_seconds=300,
    current_time=None,   # injectable for testing
) -> None
```

Raises `InvalidTimestampError` or `InvalidSignatureError` (both subclass `AegisWebhookError`) on failure. Returns `None` on success.
