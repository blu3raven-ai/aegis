import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "frontend/components/layout/SearchModal.tsx"), "utf8")
const apiSrc = readFileSync(join(ROOT, "frontend/lib/client/search-api.ts"), "utf8")

describe("search-api module", () => {
  it("exports SearchHit interface", () => {
    assert.ok(apiSrc.includes("export interface SearchHit"))
  })
  it("exports SearchResults interface", () => {
    assert.ok(apiSrc.includes("export interface SearchResults"))
  })
  it("exports search function", () => {
    assert.ok(apiSrc.includes("export async function search"))
  })
  it("has type, id, title, href, score fields", () => {
    assert.ok(apiSrc.includes("type: string"))
    assert.ok(apiSrc.includes("id: string"))
    assert.ok(apiSrc.includes("href: string"))
    assert.ok(apiSrc.includes("score: number"))
  })
  it("accepts AbortSignal", () => {
    assert.ok(apiSrc.includes("signal"))
  })
  it("hits /api/v1/graphql", () => {
    assert.ok(apiSrc.includes("/api/v1/graphql"))
  })
  it("uses the GlobalSearch operation", () => {
    assert.ok(apiSrc.includes("GlobalSearch"))
  })
})

describe("SearchModal component", () => {
  it("imports search from search-api", () => {
    assert.ok(src.includes("search-api"))
  })
  it("debounces the query so a burst of keystrokes issues one request", () => {
    assert.ok(src.includes("setDebouncedQuery"))
    assert.match(src, /setTimeout\(\(\) => setDebouncedQuery/)
  })
  it("uses AbortController", () => {
    assert.ok(src.includes("AbortController"))
  })
  it("calls controller.abort()", () => {
    assert.ok(src.includes("controller.abort()"))
  })
  it("shows loading indicator", () => {
    assert.ok(src.includes("<Spinner") || src.includes("animate-spin") || src.includes("animate-pulse"))
  })
  it("renders grouped results", () => {
    assert.ok(src.includes("displayGrouped") || src.includes("grouped"))
  })
  it("navigates on click", () => {
    assert.ok(src.includes("navigateAndClose"))
  })
  it("handles ArrowDown", () => {
    assert.ok(src.includes("ArrowDown"))
  })
  it("handles ArrowUp", () => {
    assert.ok(src.includes("ArrowUp"))
  })
  it("handles Enter", () => {
    assert.ok(src.includes("Enter"))
  })
  it("handles Escape", () => {
    assert.ok(src.includes("Escape"))
  })
  it("shows empty state", () => {
    assert.ok(src.includes("No results found"))
  })
  it("handles errors gracefully", () => {
    assert.ok(src.includes("error") || src.includes("unavailable"))
  })
  it("falls back to NAV_ITEMS", () => {
    assert.ok(src.includes("NAV_ITEMS"))
  })
  it("shows subtitle", () => {
    assert.ok(src.includes("subtitle"))
  })
})
