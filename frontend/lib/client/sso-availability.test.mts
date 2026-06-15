import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./sso-availability.ts", import.meta.url), "utf8")

test("useSsoAvailability fetches /api/v1/sso/sso-availability", () => {
  assert.match(SRC, /\/api\/v1\/sso\/sso-availability/)
})

test("hook returns enabled + protocol", () => {
  assert.match(SRC, /enabled:\s*boolean/)
  assert.match(SRC, /protocol:\s*"saml"\s*\|\s*"oidc"\s*\|\s*null/)
})

test("login URL helper maps protocol to the correct route", () => {
  assert.match(SRC, /\/auth\/sso\/saml\/login/)
  assert.match(SRC, /\/auth\/sso\/oidc\/login/)
})
