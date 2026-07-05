import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./NotificationsPanel.tsx", import.meta.url), "utf8")

test("Notifications wires the three live toggles through the save bar", () => {
  assert.match(SRC, /saveNotifications/)
  assert.match(SRC, /useSaveBarSection/)
  for (const key of ["assignments", "mentions", "kev"]) {
    assert.match(SRC, new RegExp(`key: "${key}"`))
  }
})

test("Weekly digest and Product updates are pinned coming-soon and disabled", () => {
  assert.match(SRC, /Weekly digest/)
  assert.match(SRC, /Product updates/)
  assert.match(SRC, /Coming soon/)
  // The coming-soon rows live in a separate disabled list, not the live prefs.
  assert.match(SRC, /COMING_SOON_PREFS/)
  assert.match(SRC, /disabled/)
})

test("Notifications preferences carry no email or Slack channel wording", () => {
  assert.doesNotMatch(SRC, /Slack/i)
  assert.doesNotMatch(SRC, /email/i)
  assert.doesNotMatch(SRC, /In-app \+/)
})
