import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

const src = readFileSync(
  fileURLToPath(new URL("./_SourceFindingsBoard.tsx", import.meta.url)),
  "utf-8",
)

describe("SourceFindingsBoard scope", () => {
  it("scopes by the canonical scopeRefs, not the raw discoveredItems", () => {
    // discoveredItems are "owner/repo"; the findings list matches the asset
    // display_name ("github:owner/repo"), so scoping by the raw items came up
    // empty. Prefer connection.scopeRefs (the canonical refs).
    assert.match(src, /connection\?\.scopeRefs\?\.length/)
    assert.match(src, /\? connection\.scopeRefs/)
  })

  it("falls back to discoveredItems for older connections without refs", () => {
    assert.match(src, /connection\?\.discoveredItems\?\.length/)
  })

  it("passes the resolved scope to FindingsBoardView", () => {
    assert.match(src, /scopeRepos=\{scopeRepos\}/)
  })
})
