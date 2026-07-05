import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./ReposDisplayOverflow.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("ReposDisplayOverflow", () => {
  it("exports a ReposSortMode union with critical / last-scan / name", () => {
    assert.match(src, /export type ReposSortMode = "critical" \| "last-scan" \| "name"/)
  })

  it("lists Critical first / Last scan / A–Z labels", () => {
    assert.match(src, /critical:\s*"Critical first"/)
    assert.match(src, /"last-scan":\s*"Last scan"/)
    assert.match(src, /name:\s*"A–Z"/)
  })

  it("closes on outside click and Escape", () => {
    assert.match(src, /addEventListener\("mousedown"/)
    assert.match(src, /e\.key === "Escape"/)
  })

  it("does not import @radix-ui (no new dependency)", () => {
    assert.doesNotMatch(src, /@radix-ui/)
  })
})
