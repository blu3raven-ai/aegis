# @aegis/webhooks (Node.js / TypeScript)

Verify [Aegis](https://github.com/blu3raven-ai/aegis) webhook signatures — HMAC-SHA256 with replay protection.

## Install

```bash
npm install @aegis/webhooks
```

## Quickstart

```typescript
import express from "express";
import { verifySignature, AegisWebhookError } from "@aegis/webhooks";

const app = express();

app.post(
  "/webhook",
  express.raw({ type: "*/*" }),
  (req, res) => {
    try {
      verifySignature(req.body, process.env.WEBHOOK_SECRET!, req.headers);
    } catch (err) {
      if (err instanceof AegisWebhookError) return res.sendStatus(400);
      throw err;
    }
    const event = JSON.parse(req.body.toString());
    // ... handle event
    res.sendStatus(200);
  },
);
```

## Rotation

Pass an array of secrets to accept either key during a rotation window:

```typescript
verifySignature(payload, [oldSecret, newSecret], headers);
```

## API

```typescript
verifySignature(
  payload: object | string | Buffer,
  secret: string | string[],
  headers: Record<string, string | string[] | undefined>,
  options?: {
    toleranceSeconds?: number;  // default 300
    currentTime?: number;       // injectable for testing
  },
): void
```

Throws `InvalidTimestampError` or `InvalidSignatureError` (both extend `AegisWebhookError`) on failure. Returns `void` on success.
