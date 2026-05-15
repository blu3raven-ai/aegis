import assert from "node:assert/strict"
import test from "node:test"
import { signInternalJwt } from "./jwt-internal.ts"

function decodeB64url(s: string): unknown {
  return JSON.parse(Buffer.from(s, "base64url").toString("utf8"))
}

test("signInternalJwt: produces a 3-part dot-separated token", () => {
  process.env.JWT_SHARED_SECRET = "a".repeat(64)
  const token = signInternalJwt("user-1", "admin")
  assert.equal(token.split(".").length, 3)
})

test("signInternalJwt: header declares HS256 algorithm", () => {
  process.env.JWT_SHARED_SECRET = "a".repeat(64)
  const [headerB64] = signInternalJwt("user-1", "admin").split(".")
  const header = decodeB64url(headerB64) as { alg: string }
  assert.equal(header.alg, "HS256")
})

test("signInternalJwt: payload carries correct sub, role, and 30s TTL", () => {
  process.env.JWT_SHARED_SECRET = "a".repeat(64)
  const before = Math.floor(Date.now() / 1000)
  const [, payloadB64] = signInternalJwt("user-42", "security").split(".")
  const payload = decodeB64url(payloadB64) as {
    sub: string
    role: string
    iat: number
    exp: number
  }
  assert.equal(payload.sub, "user-42")
  assert.equal(payload.role, "security")
  assert.ok(payload.iat >= before)
  assert.equal(payload.exp - payload.iat, 30)
})

test("signInternalJwt: throws in production when JWT_SHARED_SECRET is missing", () => {
  const savedSecret = process.env.JWT_SHARED_SECRET
  const savedEnv = process.env.NODE_ENV
  delete process.env.JWT_SHARED_SECRET
  // Bypass read-only check for NODE_ENV in tests
  ;(process.env as any)["NODE_ENV"] = "production"
  try {
    assert.throws(() => signInternalJwt("u", "viewer"), /JWT_SHARED_SECRET/)
  } finally {
    if (savedSecret !== undefined) process.env.JWT_SHARED_SECRET = savedSecret
    ;(process.env as any)["NODE_ENV"] = savedEnv
  }
})

test("signInternalJwt: uses dev-secret fallback outside production", () => {
  const savedSecret = process.env.JWT_SHARED_SECRET
  const savedEnv = process.env.NODE_ENV
  delete process.env.JWT_SHARED_SECRET
  ;(process.env as any)["NODE_ENV"] = "development"
  try {
    const token = signInternalJwt("u", "viewer")
    assert.equal(token.split(".").length, 3)
  } finally {
    if (savedSecret !== undefined) process.env.JWT_SHARED_SECRET = savedSecret
    ;(process.env as any)["NODE_ENV"] = savedEnv
  }
})
