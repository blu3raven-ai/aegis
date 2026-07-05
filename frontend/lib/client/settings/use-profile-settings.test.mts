import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./use-profile-settings.ts", import.meta.url), "utf8")

test("useProfileSettings fetches /api/v1/settings/account/profile via REST", () => {
  assert.match(SRC, /apiClient/)
  assert.match(SRC, /\/api\/v1\/settings\/account\/profile/)
})

test("useProfileSettings exposes saveProfile via PATCH /api/v1/settings/account/profile", () => {
  assert.match(SRC, /export async function saveProfile/)
  assert.match(SRC, /method:\s*"PATCH"/)
})

test("useProfileSettings exposes mutate to refresh after save", () => {
  assert.match(SRC, /export function useProfileSettings/)
  assert.match(SRC, /mutate/)
})
