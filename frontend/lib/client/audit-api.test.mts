import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./audit-api.ts", import.meta.url), "utf8")

test("audit-api forwards the free-text q search param", () => {
  assert.match(SRC, /q\?:\s*string/)
  assert.match(SRC, /params\.set\("q", filters\.q\)/)
})

test("audit-api exposes the facets endpoint for filter vocabularies", () => {
  assert.match(SRC, /export async function listAuditFacets/)
  assert.match(SRC, /\/api\/v1\/settings\/audit\/facets/)
})
