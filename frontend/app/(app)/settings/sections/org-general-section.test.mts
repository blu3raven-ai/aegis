import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(
  new URL("./OrgGeneralSection.tsx", import.meta.url),
  "utf8",
)

test("OrgGeneralSection wraps SettingsSection with id=general", () => {
  assert.match(SRC, /from\s+"@\/components\/settings\/SettingsSection"/)
  assert.match(SRC, /<SettingsSection/)
  assert.match(SRC, /id="general"/)
})

test("OrgGeneralSection no longer renders the ComingSoonNote", () => {
  assert.doesNotMatch(SRC, /<ComingSoonNote/)
})

test("OrgGeneralSection renders the org-level fields", () => {
  for (const label of [
    "Organization name",
    "Slug",
    "Logo",
    "Default time zone",
    "Data residency",
    "Security contact",
  ]) {
    assert.match(SRC, new RegExp(`label="${label}"`))
  }
})

test("OrgGeneralSection sanitises slug input to lowercase + dashes", () => {
  // The slug is the URL identifier — anything other than [a-z0-9-] must be
  // stripped on input so we don't end up with surprises in URLs.
  assert.match(SRC, /toLowerCase\(\)\.replace\(\/\[\^a-z0-9-\]\/g, ""\)/)
})

test("OrgGeneralSection warns that residency is locked after first scan", () => {
  // This is a real constraint of the backend's data partitioning; making it
  // visible in the UI prevents support tickets.
  assert.match(SRC, /Locked after the first scan/)
})

test("OrgGeneralSection splits identity and defaults into separate cards", () => {
  // Two SettingsCard inner cards group identity (name/slug/logo) and
  // defaults (timezone/residency/contact) so the long form reads as two
  // short cards, each with its own sub-heading.
  assert.match(SRC, /from\s+"@\/components\/settings\/SettingsCard"/)
  assert.match(SRC, /heading="Identity"/)
  assert.match(SRC, /heading="Defaults"/)
})
