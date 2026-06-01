/**
 * HMAC-SHA256 signature verification for Aegis webhook deliveries.
 *
 * Mirrors the signing logic in backend/src/notifications/webhook_signing.py so
 * receivers can validate authenticity and replay protection without rolling
 * their own crypto.
 */
import { createHmac, timingSafeEqual } from "crypto";

export class AegisWebhookError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AegisWebhookError";
  }
}

export class InvalidTimestampError extends AegisWebhookError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidTimestampError";
  }
}

export class InvalidSignatureError extends AegisWebhookError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidSignatureError";
  }
}

export interface VerifyOptions {
  /** Maximum age of a delivery in seconds. Default: 300 (5 minutes). */
  toleranceSeconds?: number;
  /**
   * Override the current Unix timestamp used for the tolerance check.
   * Intended for unit testing only — allows freezing time without mocking.
   */
  currentTime?: number;
}

/**
 * Return a lowercase-keyed lookup from arbitrary header maps.
 *
 * WHY: RFC 7230 §3.2 declares HTTP header names case-insensitive; different
 * frameworks (Express, Fastify, Hono, …) may preserve original casing.
 */
function normaliseHeaders(headers: Record<string, string | string[] | undefined>): Map<string, string> {
  const map = new Map<string, string>();
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    // Take the first value if the framework provides an array (e.g. multi-value)
    map.set(key.toLowerCase(), Array.isArray(value) ? value[0] : value);
  }
  return map;
}

/**
 * Return canonical JSON matching Phase 44's sign_payload serialisation.
 *
 * WHY: Keys must be sorted alphabetically with no whitespace so the signed
 * string is byte-for-byte identical to what the server produced.
 */
function canonicalJson(payload: object): string {
  // Deep-clone via JSON round-trip so we can sort keys at every nesting level
  const clone = JSON.parse(JSON.stringify(payload)) as object;
  return JSON.stringify(clone, Object.keys(clone).sort() as never);
}

/**
 * Recursively sort the keys of a JSON object so nested objects are also sorted.
 * Used to produce canonical JSON that matches Python's json.dumps(sort_keys=True).
 */
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

/**
 * Return canonical JSON with all object keys sorted recursively.
 *
 * WHY: Phase 44 uses Python's sort_keys=True which sorts at every nesting
 * level; a single top-level sort is insufficient for nested objects.
 */
function canonicalJsonDeep(payload: object | string | Buffer): string {
  let obj: unknown;
  if (Buffer.isBuffer(payload)) {
    obj = JSON.parse(payload.toString("utf8"));
  } else if (typeof payload === "string") {
    obj = JSON.parse(payload);
  } else {
    obj = payload;
  }
  return JSON.stringify(sortObjectKeys(obj));
}

/**
 * Compute v1=<hex> for a given secret and signed string.
 *
 * WHY: Extracted to keep the comparison loop readable and avoid repeating the
 * HMAC construction.
 */
function computeSignature(secret: string, signedString: string): string {
  const hex = createHmac("sha256", secret)
    .update(signedString, "utf8")
    .digest("hex");
  return `v1=${hex}`;
}

/**
 * Verify an Aegis webhook signature.
 *
 * Throws `InvalidTimestampError` or `InvalidSignatureError` on failure.
 * Returns `void` on success.
 *
 * @param payload  Raw request body as `Buffer` / `string`, or already-parsed
 *                 JSON object.  Bytes/strings are re-parsed to produce canonical JSON.
 * @param secret   A single signing secret string, or an array of secrets
 *                 (pass `[oldSecret, newSecret]` during a rotation window).
 * @param headers  The HTTP request headers.  Lookup is case-insensitive.
 * @param options  Optional tolerance window and time override for testing.
 */
export function verifySignature(
  payload: object | string | Buffer,
  secret: string | string[],
  headers: Record<string, string | string[] | undefined>,
  options?: VerifyOptions,
): void {
  const { toleranceSeconds = 300, currentTime } = options ?? {};
  const normalised = normaliseHeaders(headers);

  // ── Extract required headers ────────────────────────────────────────────
  const timestampStr = normalised.get("x-aegis-timestamp");
  const signatureHeader = normalised.get("x-aegis-signature");

  if (timestampStr === undefined || signatureHeader === undefined) {
    throw new AegisWebhookError(
      "Missing required headers: X-Aegis-Timestamp and X-Aegis-Signature must be present",
    );
  }

  // ── Validate timestamp ──────────────────────────────────────────────────
  const ts = Number(timestampStr);
  if (!Number.isInteger(ts) || String(ts) !== timestampStr) {
    throw new InvalidTimestampError(
      `X-Aegis-Timestamp is not a valid integer: ${JSON.stringify(timestampStr)}`,
    );
  }

  const now = currentTime ?? Math.floor(Date.now() / 1000);
  const age = now - ts;
  if (Math.abs(age) > toleranceSeconds) {
    throw new InvalidTimestampError(
      `Timestamp is outside the tolerance window (age=${age}s, tolerance=${toleranceSeconds}s)`,
    );
  }

  // ── Build signed string ─────────────────────────────────────────────────
  const canonical = canonicalJsonDeep(payload);
  const signedString = `${timestampStr}.${canonical}`;

  // ── Collect candidate v1=<hex> values from the header ───────────────────
  // WHY: Rotation sends multiple comma-separated signatures; we accept any match.
  const candidates = signatureHeader
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  // ── Verify against each secret × each candidate signature ───────────────
  const secrets = Array.isArray(secret) ? secret : [secret];
  for (const rawSecret of secrets) {
    const expected = computeSignature(rawSecret, signedString);
    const expectedBuf = Buffer.from(expected, "utf8");

    for (const candidate of candidates) {
      const candidateBuf = Buffer.from(candidate, "utf8");
      // WHY: timingSafeEqual prevents timing-based secret leakage — buffers
      // must be the same length, so length mismatch is checked first.
      if (
        expectedBuf.length === candidateBuf.length &&
        timingSafeEqual(expectedBuf, candidateBuf)
      ) {
        return; // Success
      }
    }
  }

  throw new InvalidSignatureError(
    "No candidate signature matched any of the provided secrets",
  );
}
