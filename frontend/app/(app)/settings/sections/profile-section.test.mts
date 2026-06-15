import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./ProfileSection.tsx", import.meta.url), "utf8")

test("ProfileSection wraps SettingsSection with id=profile", () => {
  assert.match(SRC, /from\s+"@\/components\/settings\/SettingsSection"/)
  assert.match(SRC, /<SettingsSection/)
  assert.match(SRC, /id="profile"/)
})

test("ProfileSection no longer uses ComingSoonNote placeholder", () => {
  assert.doesNotMatch(SRC, /<ComingSoonNote/)
})

test("ProfileSection renders only personal preferences", () => {
  // Profile is preferences-only. Avatar, display name, and email live on
  // AccountContent under Security & sessions to avoid duplicate edit modals.
  for (const label of ["Time zone", "Theme"]) {
    assert.match(SRC, new RegExp(`label="${label}"`))
  }
})

test("ProfileSection no longer renders identity rows that AccountContent owns", () => {
  // Drop the duplicated Avatar / Display name / Email rows — they're rendered
  // by AccountContent under Security & sessions.
  for (const label of ["Avatar", "Display name", "Email", "Default landing page"]) {
    assert.doesNotMatch(SRC, new RegExp(`label="${label}"`))
  }
})

test("ProfileSection uses the SettingsCard + SettingsRow primitives", () => {
  assert.match(SRC, /from\s+"@\/components\/settings\/SettingsCard"/)
  assert.match(SRC, /from\s+"@\/components\/settings\/SettingsRow"/)
})

test("ProfileSection sources persisted preferences from useProfileSettings", () => {
  assert.match(SRC, /from\s+"@\/lib\/client\/settings\/use-profile-settings"/)
  assert.match(SRC, /useProfileSettings\(\)/)
})

test("ProfileSection no longer reads or writes localStorage", () => {
  assert.doesNotMatch(SRC, /localStorage/)
  assert.doesNotMatch(SRC, /THEME_STORAGE_KEY/)
  assert.doesNotMatch(SRC, /TZ_STORAGE_KEY/)
})

test("ProfileSection registers with the global SaveBar provider", () => {
  assert.match(SRC, /from\s+"@\/app\/\(app\)\/settings\/save-bar\/SaveBarProvider"/)
  assert.match(SRC, /useSaveBarSection\(/)
})
