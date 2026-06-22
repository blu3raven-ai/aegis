import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./use-notification-settings.ts", import.meta.url), "utf8")

test("useNotificationSettings fetches /api/v1/settings/account/notification-prefs via REST", () => {
  assert.match(SRC, /apiClient/)
  assert.match(SRC, /\/api\/v1\/settings\/account\/notification-prefs/)
})

test("useNotificationSettings exposes saveNotifications via PATCH /api/v1/settings/account/notification-prefs", () => {
  assert.match(SRC, /export async function saveNotifications/)
  assert.match(SRC, /method:\s*"PATCH"/)
})

test("useNotificationSettings exports the toggle shape", () => {
  assert.match(SRC, /assignments: boolean/)
  assert.match(SRC, /mentions: boolean/)
  assert.match(SRC, /kev: boolean/)
  assert.match(SRC, /weeklyDigest: boolean/)
  assert.match(SRC, /marketing: boolean/)
})
