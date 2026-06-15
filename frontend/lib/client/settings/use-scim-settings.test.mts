import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./use-scim-settings.ts", import.meta.url), "utf8")

test("useScimSettings fetches /api/v1/settings/scim", () => {
  assert.match(SRC, /apiClient<.*>\("\/api\/v1\/settings\/scim"/)
})

test("useScimSettings exposes save + generate + clear helpers", () => {
  assert.match(SRC, /export async function saveScimSettings/)
  assert.match(SRC, /export async function generateScimToken/)
  assert.match(SRC, /export async function clearScimToken/)
})

test("ScimSettings interface has the right shape", () => {
  for (const field of ["enabled", "defaultRoleId", "tokenSet", "scimEndpointUrl"]) {
    assert.match(SRC, new RegExp(`${field}:`))
  }
})
