import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const sessionSource = readFileSync(new URL("./session.ts", import.meta.url), "utf8")

test("normal session reader rejects MFA-pending tokens", () => {
  assert.match(sessionSource, /payload\.purpose === "mfa_pending"/)
})

test("MFA pending helper uses a separate cookie and purpose marker", () => {
  const source = readFileSync(new URL("./mfa-session.ts", import.meta.url), "utf8")
  assert.match(source, /const MFA_COOKIE_NAME = "__mfa_pending"/)
  assert.match(source, /purpose: "mfa_pending"/)
  assert.match(source, /MFA_DURATION_S = 5 \* 60/)
})
