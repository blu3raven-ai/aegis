import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./ScimTokenModal.tsx", import.meta.url), "utf8")

test("ScimTokenModal shows the raw token once", () => {
  assert.match(SRC, /token/i)
  assert.match(SRC, /Copy/i)
})

test("ScimTokenModal has a confirm-saved button", () => {
  assert.match(SRC, /I've saved it|Done/i)
})
