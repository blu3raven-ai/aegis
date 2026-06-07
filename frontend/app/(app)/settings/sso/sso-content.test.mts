import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./SsoContent.tsx", import.meta.url), "utf8")

test("SsoContent no longer hides the surface behind an Enterprise gate", () => {
  // The configured-SSO panel renders for every tier now; admins can wire up
  // identity providers regardless of plan.
  assert.doesNotMatch(SRC, /EnterpriseGate/)
  assert.doesNotMatch(SRC, /useLicense/)
})

test("SsoContent renders the enforced-SSO status banner", () => {
  assert.match(SRC, /SSO is enforced for your organization/)
})

test("SsoContent offers the standard identity providers", () => {
  for (const provider of [
    "Google Workspace",
    "Microsoft Entra ID",
    "Okta",
    "OneLogin",
    "JumpCloud",
    "SAML 2.0 \\(generic\\)",
  ]) {
    assert.match(SRC, new RegExp(`"${provider}"`))
  }
})

test("SsoContent uses the SettingsCard / SettingsRow / ToggleSwitch primitives", () => {
  assert.match(SRC, /from\s+"@\/components\/settings\/SettingsCard"/)
  assert.match(SRC, /from\s+"@\/components\/settings\/SettingsRow"/)
  assert.match(SRC, /from\s+"@\/components\/settings\/ToggleSwitch"/)
})

test("SsoContent has an audit-log streaming URL input", () => {
  assert.match(SRC, /Audit log streaming/)
  assert.match(SRC, /type="url"/)
})

test("SsoContent no longer renders the 'In development' placeholder", () => {
  assert.doesNotMatch(SRC, /In development/)
  assert.doesNotMatch(SRC, /SSO configuration is not available yet/)
})
