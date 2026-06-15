import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./use-audit-stream-settings.ts", import.meta.url), "utf8")

test("hook fetches /api/v1/settings/audit-stream", () => {
  assert.match(SRC, /\/api\/v1\/settings\/audit-stream/)
})

test("exposes save + test helpers", () => {
  assert.match(SRC, /export async function saveAuditStreamSettings/)
  assert.match(SRC, /export async function testAuditStream/)
})

test("interface includes the right shape", () => {
  for (const field of ["enabled", "targetType", "endpointUrl", "authTokenSet", "lastEventId"]) {
    assert.match(SRC, new RegExp(`${field}:`))
  }
})
