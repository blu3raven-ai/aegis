import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const page = readFileSync(new URL("./page.tsx", import.meta.url), "utf8")

test("settings page no longer redirects", () => {
  assert.doesNotMatch(page, /redirect\(/)
})

test("settings page renders SettingsInPageNav", () => {
  assert.match(page, /SettingsInPageNav/)
})

// Personal API tokens were consolidated into the org-level Security & Audit
// > API tokens row, so the section no longer renders here. Members / Roles /
// Teams were promoted to top-level routes (/members, /roles, /teams).
const SECTIONS = [
  "ProfileSection",
  "NotificationsPreferencesSection",
  "SecuritySessionsSection",
  "OrgGeneralSection",
  "SsoSection",
  "AuditLogSection",
  "ApiKeysSection",
  "RunnersSection",
  "LlmSection",
  "LicenseSection",
] as const

for (const s of SECTIONS) {
  test(`settings page renders ${s}`, () => {
    assert.match(page, new RegExp(`<${s}\\s*/>`))
  })
}

test("settings page renders a PageHeader", () => {
  assert.match(page, /PageHeader/)
})
