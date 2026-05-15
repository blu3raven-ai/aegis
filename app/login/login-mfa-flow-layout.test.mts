import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

test("login route issues pending MFA instead of a full session for 2FA users", () => {
  const source = readFileSync(new URL("../api/login/route.ts", import.meta.url), "utf8")
  assert.match(source, /createMfaSession\(user\.id\)/)
  assert.match(source, /requiresMfa: true/)
  assert.match(source, /user\.totpEnabled && user\.totpSecret/)
})

test("login route uses username-or-email invalid credentials copy", () => {
  const source = readFileSync(new URL("../api/login/route.ts", import.meta.url), "utf8")

  assert.match(source, /Invalid username, email, or password/)
})

test("login form navigates to the verification step when MFA is required", () => {
  const source = readFileSync(new URL("./LoginForm.tsx", import.meta.url), "utf8")
  assert.match(source, /data\.requiresMfa/)
  assert.match(source, /router\.push\("\/login\/verify"\)/)
})

test("login form uses username-or-email credentials and a password visibility control", () => {
  const source = readFileSync(new URL("./LoginForm.tsx", import.meta.url), "utf8")

  assert.match(source, /Email or username/)
  assert.match(source, /type="text"/)
  assert.match(source, /autoComplete="username"/)
  assert.match(source, /identifier: email/)
  assert.match(source, /showPassword \? "text" : "password"/)
  assert.match(source, /aria-label=\{showPassword \? "Hide password" : "Show password"\}/)
  assert.match(source, /setShowPassword\(\(value\) => !value\)/)
  assert.doesNotMatch(source, /Continue with GitHub/)
  assert.doesNotMatch(source, /\/api\/login\/github\/start/)
})

test("login verify route validates TOTP and creates the full session", () => {
  const source = readFileSync(new URL("../api/login/verify/route.ts", import.meta.url), "utf8")
  assert.match(source, /getMfaSession\(\)/)
  assert.match(source, /verifyTotpCode\(code, user\.totpSecret\)/)
  assert.match(source, /createSession\(user\)/)
  assert.match(source, /clearMfaSession\(\)/)
})
