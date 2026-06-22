import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./use-auth-security.ts", import.meta.url), "utf8")

test("useAuthSecurity fetches /api/v1/settings/auth-security", () => {
  assert.match(SRC, /apiClient<.*>\("\/api\/v1\/settings\/auth-security"/)
})

test("useAuthSecurity exposes saveAuthSecurity via PATCH", () => {
  assert.match(SRC, /method: "PATCH"/)
  assert.match(SRC, /export async function saveAuthSecurity/)
})

test("useAuthSecurity exports the four controls", () => {
  assert.match(SRC, /requireMfaManualUsers: boolean/)
  assert.match(SRC, /requireMfaAdmins: boolean/)
  assert.match(SRC, /trustedSessionDurationDays: number/)
  assert.match(SRC, /recoveryCodePolicy: RecoveryCodePolicy/)
})

test("useAuthSecurity surfaces GqlError instead of silently returning defaults", () => {
  // Prior behavior swallowed PERMISSION_DENIED into a DEFAULTS object so non-admins
  // saw bogus values; the hook now exposes `error: GqlError | null` so the consumer
  // can render a denied state.
  assert.match(SRC, /error: GqlError \| null/)
  assert.doesNotMatch(SRC, /return DEFAULTS/)
})
