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
  for (const label of ["Organization name", "Logo"]) {
    assert.match(SRC, new RegExp(`label="${label}"`))
  }
})

test("OrgGeneralSection drops dead rows", () => {
  for (const dropped of [
    'label="Slug"',
    'label="Data residency"',
    'label="Subtitle"',
    'label="Default time zone"',
    'label="Security contact"',
    "Locked after the first scan",
  ]) {
    assert.doesNotMatch(SRC, new RegExp(dropped))
  }
})

test("OrgGeneralSection sources state from useOrgSettings", () => {
  assert.match(SRC, /from\s+"@\/lib\/client\/settings\/use-org-settings"/)
  assert.match(SRC, /useOrgSettings\(\)/)
})

test("OrgGeneralSection registers with the global SaveBar provider", () => {
  assert.match(SRC, /from\s+"@\/app\/\(app\)\/settings\/save-bar\/SaveBarProvider"/)
  assert.match(SRC, /useSaveBarSection\(/)
})

test("OrgGeneralSection wires logo upload and clear via the hook helpers", () => {
  assert.match(SRC, /setOrgLogo/)
  assert.match(SRC, /clearOrgLogo/)
})

test("OrgGeneralSection shows Blu3Raven as the input placeholder only", () => {
  assert.match(SRC, /placeholder="Blu3Raven"/)
  assert.doesNotMatch(SRC, /=== "Blu3Raven"/)
})

test("OrgGeneralSection hints that a blank name uses the default branding", () => {
  assert.match(SRC, /default Aegis branding/i)
  assert.match(SRC, /Leave blank/i)
})

test("OrgGeneralSection clears name to null when input is empty", () => {
  assert.match(SRC, /name: e\.target\.value \|\| null/)
})
