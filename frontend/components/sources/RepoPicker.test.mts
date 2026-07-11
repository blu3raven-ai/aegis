import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(fileURLToPath(new URL("./RepoPicker.tsx", import.meta.url)), "utf-8")

describe("RepoPicker", () => {
  it("groups repos by owner and searches across all owners", () => {
    assert.match(src, /function ownerOf/)
    assert.match(src, /toLowerCase\(\)\.includes/)
  })
  it("supports per-group select-all and a running selection count", () => {
    assert.match(src, /Select all|Clear all/)
    assert.match(src, /selected across/)
  })
  it("surfaces newly-available repos (allow-list + notify)", () => {
    assert.match(src, /new repos available since last sync/)
    assert.match(src, /Add all new/)
  })
  it("accepts public repos by https clone URL", () => {
    assert.match(src, /Add a public repo/)
    assert.match(src, /\^https:/)
  })
  it("disables confirm when nothing is selected", () => {
    assert.match(src, /disabled=\{selected\.size === 0\}/)
  })
})

describe("RepoPicker public-URL validation", () => {
  it("verifies a GitHub repo exists before adding it", () => {
    assert.match(src, /api\.github\.com\/repos/)
    assert.match(src, /doesn't exist or is private/)
    assert.match(src, /setUrlError/)
  })
})
