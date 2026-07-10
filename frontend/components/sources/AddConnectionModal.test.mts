import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(fileURLToPath(new URL("./AddConnectionModal.tsx", import.meta.url)), "utf-8")

describe("AddConnectionModal", () => {
  it("routes a tested connection into the repo picker and saves selected scope", () => {
    assert.match(src, /"pick-repos"/)
    assert.match(src, /<RepoPicker/)
    assert.match(src, /scanScope: "selected"/)
    assert.match(src, /includedItems: included/)
  })
})
