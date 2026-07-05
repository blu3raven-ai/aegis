/**
 * Tests for verifySignature.
 *
 * All tests build signatures using the same primitive as Phase 44's
 * sign_payload so we exercise the full sign → verify round-trip without
 * importing any backend code.
 */
import { createHmac } from "crypto";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { describe, it, expect } from "vitest";

import {
  verifySignature,
  AegisWebhookError,
  InvalidSignatureError,
  InvalidTimestampError,
} from "../src/index.js";

// ── Helpers that mirror Phase 44's sign_payload ───────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));

const TEST_SECRET = "test-secret-123";
const ALT_SECRET = "alt-secret-456";

function sortObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortObjectKeys);
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return Object.keys(obj)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => {
        acc[k] = sortObjectKeys(obj[k]);
        return acc;
      }, {});
  }
  return value;
}

function canonical(payload: object): string {
  return JSON.stringify(sortObjectKeys(payload));
}

function sign(payload: object, secret: string, ts: number): string {
  const signed = `${ts}.${canonical(payload)}`;
  const hex = createHmac("sha256", secret).update(signed, "utf8").digest("hex");
  return `v1=${hex}`;
}

function makeHeaders(sig: string, ts: number): Record<string, string> {
  return {
    "X-Aegis-Timestamp": String(ts),
    "X-Aegis-Signature": sig,
    "X-Aegis-Signature-Version": "1",
  };
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

// ── Load sample payload ───────────────────────────────────────────────────────

const SAMPLE_PAYLOAD = JSON.parse(
  readFileSync(join(__dirname, "fixtures/samplePayload.json"), "utf8"),
) as object;

// ── Happy path ────────────────────────────────────────────────────────────────

describe("happy path", () => {
  it("verifies a valid object payload", () => {
    const ts = nowSec();
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, makeHeaders(sig, ts)),
    ).not.toThrow();
  });

  it("verifies a valid Buffer payload", () => {
    const ts = nowSec();
    const buf = Buffer.from(JSON.stringify(SAMPLE_PAYLOAD), "utf8");
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    expect(() =>
      verifySignature(buf, TEST_SECRET, makeHeaders(sig, ts)),
    ).not.toThrow();
  });

  it("verifies a valid string payload", () => {
    const ts = nowSec();
    const str = JSON.stringify(SAMPLE_PAYLOAD);
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    expect(() =>
      verifySignature(str, TEST_SECRET, makeHeaders(sig, ts)),
    ).not.toThrow();
  });

  it("returns void (undefined) on success", () => {
    const ts = nowSec();
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    const result = verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, makeHeaders(sig, ts));
    expect(result).toBeUndefined();
  });
});

// ── Tampered payload ──────────────────────────────────────────────────────────

describe("tampered payload", () => {
  it("throws InvalidSignatureError when payload is modified", () => {
    const ts = nowSec();
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    const tampered = { ...SAMPLE_PAYLOAD, event: "finding.deleted" };
    expect(() =>
      verifySignature(tampered, TEST_SECRET, makeHeaders(sig, ts)),
    ).toThrow(InvalidSignatureError);
  });

  it("throws InvalidSignatureError with wrong secret", () => {
    const ts = nowSec();
    const sig = sign(SAMPLE_PAYLOAD, "wrong-secret", ts);
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, makeHeaders(sig, ts)),
    ).toThrow(InvalidSignatureError);
  });
});

// ── Timestamp validation ──────────────────────────────────────────────────────

describe("timestamp validation", () => {
  it("throws InvalidTimestampError for expired timestamps", () => {
    const ts = nowSec() - 400; // beyond 300s tolerance
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, makeHeaders(sig, ts)),
    ).toThrow(InvalidTimestampError);
  });

  it("throws InvalidTimestampError for future timestamps beyond tolerance", () => {
    const ts = nowSec() + 400;
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, makeHeaders(sig, ts)),
    ).toThrow(InvalidTimestampError);
  });

  it("accepts a timestamp at the boundary of the tolerance window", () => {
    const ts = nowSec() - 299;
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, makeHeaders(sig, ts)),
    ).not.toThrow();
  });

  it("throws InvalidTimestampError for non-integer timestamp", () => {
    const ts = nowSec();
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    const headers = { ...makeHeaders(sig, ts), "X-Aegis-Timestamp": "not-a-number" };
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, headers),
    ).toThrow(InvalidTimestampError);
  });

  it("currentTime option freezes the clock for testing", () => {
    const ts = 1_700_000_000;
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    // Same frozen time → passes
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, makeHeaders(sig, ts), {
        currentTime: ts,
      }),
    ).not.toThrow();
    // Frozen time outside window → fails
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, makeHeaders(sig, ts), {
        currentTime: ts + 400,
      }),
    ).toThrow(InvalidTimestampError);
  });
});

// ── Case-insensitive headers ──────────────────────────────────────────────────

describe("case-insensitive headers", () => {
  it("accepts lowercase header names", () => {
    const ts = nowSec();
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    const headers = {
      "x-aegis-timestamp": String(ts),
      "x-aegis-signature": sig,
    };
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, headers),
    ).not.toThrow();
  });

  it("accepts mixed-case header names", () => {
    const ts = nowSec();
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    const headers = {
      "X-Aegis-Timestamp": String(ts),
      "x-aegis-signature": sig,
    };
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, headers),
    ).not.toThrow();
  });
});

// ── Multiple signatures (rotation) ───────────────────────────────────────────

describe("multiple signatures in header", () => {
  it("accepts delivery when any candidate signature matches", () => {
    const ts = nowSec();
    const sig1 = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    const sig2 = sign(SAMPLE_PAYLOAD, ALT_SECRET, ts);
    const combined = `${sig1},${sig2}`;
    // Only TEST_SECRET provided — matches sig1
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, makeHeaders(combined, ts)),
    ).not.toThrow();
  });

  it("throws when no candidate matches", () => {
    const ts = nowSec();
    const sig1 = sign(SAMPLE_PAYLOAD, "bad1", ts);
    const sig2 = sign(SAMPLE_PAYLOAD, "bad2", ts);
    const combined = `${sig1},${sig2}`;
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, makeHeaders(combined, ts)),
    ).toThrow(InvalidSignatureError);
  });
});

// ── Multiple secrets (rotation — pass array) ──────────────────────────────────

describe("multiple secrets (array)", () => {
  it("accepts when any secret in the list produces a matching signature", () => {
    const ts = nowSec();
    const sig = sign(SAMPLE_PAYLOAD, ALT_SECRET, ts);
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, [TEST_SECRET, ALT_SECRET], makeHeaders(sig, ts)),
    ).not.toThrow();
  });

  it("throws when no secret in the list produces a match", () => {
    const ts = nowSec();
    const sig = sign(SAMPLE_PAYLOAD, "unrelated-secret", ts);
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, [TEST_SECRET, ALT_SECRET], makeHeaders(sig, ts)),
    ).toThrow(InvalidSignatureError);
  });

  it("handles rotation where both header and secret list have two entries", () => {
    const ts = nowSec();
    const sigOld = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    const sigNew = sign(SAMPLE_PAYLOAD, ALT_SECRET, ts);
    const combined = `${sigOld},${sigNew}`;
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, [TEST_SECRET, ALT_SECRET], makeHeaders(combined, ts)),
    ).not.toThrow();
  });
});

// ── Missing headers ───────────────────────────────────────────────────────────

describe("missing headers", () => {
  it("throws AegisWebhookError when X-Aegis-Timestamp is absent", () => {
    const ts = nowSec();
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, { "X-Aegis-Signature": sig }),
    ).toThrow(AegisWebhookError);
  });

  it("throws AegisWebhookError when X-Aegis-Signature is absent", () => {
    const ts = nowSec();
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, { "X-Aegis-Timestamp": String(ts) }),
    ).toThrow(AegisWebhookError);
  });

  it("throws AegisWebhookError with empty headers", () => {
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, {}),
    ).toThrow(AegisWebhookError);
  });
});

// ── Timing-safe comparison ────────────────────────────────────────────────────

describe("timing-safe comparison", () => {
  it("rejects candidates of different byte lengths without timing leak", () => {
    // WHY: timingSafeEqual requires equal-length buffers — we verify that
    // length mismatch is handled safely (does not throw a buffer error, just fails).
    const ts = nowSec();
    const headers = {
      "X-Aegis-Timestamp": String(ts),
      // Deliberately short — will not match any v1=<64-char-hex> expected value
      "X-Aegis-Signature": "v1=short",
    };
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, headers),
    ).toThrow(InvalidSignatureError);
  });

  it("does not accept equal-length but different signatures", () => {
    const ts = nowSec();
    // Produce a valid-length but wrong signature
    const wrongHex = "a".repeat(64);
    const headers = {
      "X-Aegis-Timestamp": String(ts),
      "X-Aegis-Signature": `v1=${wrongHex}`,
    };
    expect(() =>
      verifySignature(SAMPLE_PAYLOAD, TEST_SECRET, headers),
    ).toThrow(InvalidSignatureError);
  });
});

// ── Express middleware integration ────────────────────────────────────────────

describe("Express middleware integration", () => {
  /**
   * Minimal Express middleware pattern — the real implementation would
   * call next(err) on failure; here we throw for simplicity in tests.
   */
  function aegisWebhookMiddleware(secret: string) {
    return (
      req: { body: Buffer; headers: Record<string, string> },
      _res: unknown,
      next: (err?: unknown) => void,
    ) => {
      try {
        verifySignature(req.body, secret, req.headers);
        next();
      } catch (err) {
        next(err);
      }
    };
  }

  it("calls next() with no error on valid request", () => {
    const ts = nowSec();
    const body = Buffer.from(JSON.stringify(SAMPLE_PAYLOAD), "utf8");
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    const req = {
      body,
      headers: makeHeaders(sig, ts),
    };

    let calledWith: unknown = "not-called";
    const next = (err?: unknown) => {
      calledWith = err;
    };

    aegisWebhookMiddleware(TEST_SECRET)(req, {}, next);
    expect(calledWith).toBeUndefined();
  });

  it("calls next(err) with InvalidSignatureError on tampered body", () => {
    const ts = nowSec();
    const body = Buffer.from(JSON.stringify(SAMPLE_PAYLOAD), "utf8");
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);

    const tamperedBody = Buffer.from(
      JSON.stringify({ ...SAMPLE_PAYLOAD, event: "injected" }),
      "utf8",
    );
    const req = { body: tamperedBody, headers: makeHeaders(sig, ts) };

    let calledWith: unknown = "not-called";
    aegisWebhookMiddleware(TEST_SECRET)(req, {}, (err) => {
      calledWith = err;
    });

    expect(calledWith).toBeInstanceOf(InvalidSignatureError);
  });

  it("calls next(err) with InvalidTimestampError on expired request", () => {
    const ts = nowSec() - 400;
    const body = Buffer.from(JSON.stringify(SAMPLE_PAYLOAD), "utf8");
    const sig = sign(SAMPLE_PAYLOAD, TEST_SECRET, ts);
    const req = { body, headers: makeHeaders(sig, ts) };

    let calledWith: unknown = "not-called";
    aegisWebhookMiddleware(TEST_SECRET)(req, {}, (err) => {
      calledWith = err;
    });

    expect(calledWith).toBeInstanceOf(InvalidTimestampError);
  });
});
