import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(new URL("./images-api.ts", import.meta.url).pathname, "utf-8")

describe("images-api shape", () => {
  it("targets the /api/v1/images endpoint", () => {
    assert.ok(src.includes("/api/v1/images"))
  })

  it("exports listImages as an async function", () => {
    assert.match(src, /export\s+async\s+function\s+listImages\b/)
  })

  it("forwards cursor and limit query params", () => {
    assert.match(src, /params\.set\("cursor"/)
    assert.match(src, /params\.set\("limit"/)
  })

  it("declares the ImageRow contract with enrichment fields", () => {
    assert.ok(src.includes("layer_count: number | null"))
    assert.ok(src.includes("size_bytes: number | null"))
    assert.ok(src.includes("base_os: string | null"))
  })
})
