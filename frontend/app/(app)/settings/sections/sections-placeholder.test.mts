import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const FILES: readonly string[] = []

// No sections currently rely on <ComingSoonNote>. Re-add filenames to FILES
// (and this set when relevant) when a new placeholder section is introduced.
const FILES_WITH_INLINE_COMING_SOON = new Set<string>()

for (const file of FILES) {
  test(`${file} wraps SettingsSection`, () => {
    const src = readFileSync(new URL(`./${file}`, import.meta.url), "utf8")
    assert.match(src, /from\s+"@\/components\/settings\/SettingsSection"/)
    assert.match(src, /<SettingsSection/)
  })

  test(`${file} marks the section as coming-soon`, () => {
    const src = readFileSync(new URL(`./${file}`, import.meta.url), "utf8")
    if (FILES_WITH_INLINE_COMING_SOON.has(file)) {
      assert.match(src, /coming soon/i)
    } else {
      assert.match(src, /<ComingSoonNote/)
      assert.match(src, /from\s+"@\/components\/settings\/ComingSoonNote"/)
    }
  })
}

test("ProfileSection has id=profile", () => {
  const src = readFileSync(new URL("./ProfileSection.tsx", import.meta.url), "utf8")
  assert.match(src, /id="profile"/)
})

test("NotificationsPreferencesSection has id=notifications", () => {
  const src = readFileSync(new URL("./NotificationsPreferencesSection.tsx", import.meta.url), "utf8")
  assert.match(src, /id="notifications"/)
})

test("SecuritySessionsSection has id=security", () => {
  const src = readFileSync(new URL("./SecuritySessionsSection.tsx", import.meta.url), "utf8")
  assert.match(src, /id="security"/)
})

test("OrgGeneralSection has id=general", () => {
  const src = readFileSync(new URL("./OrgGeneralSection.tsx", import.meta.url), "utf8")
  assert.match(src, /id="general"/)
})
