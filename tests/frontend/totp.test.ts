import test from "node:test"
import assert from "node:assert/strict"
import { generateSync } from "otplib"
import { generateTotpSecret, buildOtpauthUri, verifyTotpCode } from "../../lib/shared/totp.ts"

test("generateTotpSecret returns a non-empty base32 string", () => {
  const secret = generateTotpSecret()
  assert.ok(secret.length > 0)
  assert.match(secret, /^[A-Z2-7]+=*$/)
})

test("buildOtpauthUri includes issuer and username", () => {
  const uri = buildOtpauthUri("JBSWY3DPEHPK3PXP", "alice")
  assert.ok(uri.startsWith("otpauth://totp/"))
  assert.ok(uri.includes("Security%20Portal") || uri.includes("Security Portal"))
  assert.ok(uri.includes("alice"))
})

test("verifyTotpCode returns true for a valid code", () => {
  const secret = generateTotpSecret()
  const code = generateSync({ secret })
  assert.ok(verifyTotpCode(code, secret))
})

test("verifyTotpCode returns false for wrong code", () => {
  const secret = generateTotpSecret()
  assert.strictEqual(verifyTotpCode("000000", secret), false)
})

test("verifyTotpCode returns false for non-numeric input", () => {
  const secret = generateTotpSecret()
  assert.strictEqual(verifyTotpCode("abcdef", secret), false)
})
