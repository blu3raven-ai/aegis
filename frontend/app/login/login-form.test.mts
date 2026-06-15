import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./LoginForm.tsx", import.meta.url), "utf8")

test("LoginForm imports useSsoAvailability", () => {
  assert.match(SRC, /from\s+"@\/lib\/client\/sso-availability"/)
  assert.match(SRC, /useSsoAvailability\(\)/)
})

test("LoginForm renders a Sign in with SSO link when SSO is enabled", () => {
  assert.match(SRC, /Sign in with SSO/i)
  assert.match(SRC, /ssoLoginUrl\(/)
})

test("SSO button render is gated on availability.enabled", () => {
  assert.match(SRC, /availability\?\.enabled/)
})
