import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./use-notification-settings.ts", import.meta.url), "utf8")

test("useNotificationSettings fetches /api/v1/settings/notifications", () => {
  assert.match(SRC, /apiClient<.*>\("\/api\/v1\/settings\/notifications"/)
})

test("useNotificationSettings exposes saveNotifications via PATCH", () => {
  assert.match(SRC, /method: "PATCH"/)
  assert.match(SRC, /export async function saveNotifications/)
})

test("useNotificationSettings exports the toggle shape", () => {
  assert.match(SRC, /assignments: boolean/)
  assert.match(SRC, /mentions: boolean/)
  assert.match(SRC, /kev: boolean/)
  assert.match(SRC, /weeklyDigest: boolean/)
  assert.match(SRC, /marketing: boolean/)
})
