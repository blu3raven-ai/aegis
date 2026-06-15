import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./use-profile-settings.ts", import.meta.url), "utf8")

test("useProfileSettings fetches /api/v1/settings/profile", () => {
  assert.match(SRC, /apiClient<.*>\("\/api\/v1\/settings\/profile"/)
})

test("useProfileSettings exposes saveProfile via PATCH", () => {
  assert.match(SRC, /method: "PATCH"/)
  assert.match(SRC, /export async function saveProfile/)
})

test("useProfileSettings exposes mutate to refresh after save", () => {
  assert.match(SRC, /export function useProfileSettings/)
  assert.match(SRC, /mutate/)
})
