import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./FindingAcceptRiskAction.tsx", import.meta.url).pathname,
  "utf-8",
)

test("uses shared primitives, never raw <button>/<input>", () => {
  assert.match(src, /from "@\/components\/ui\/Button"/)
  assert.doesNotMatch(src, /<button[\s>]/)
  assert.doesNotMatch(src, /<input[\s>]/)
})

test("calls the createAcceptedRisk client", () => {
  assert.match(src, /createAcceptedRisk/)
})

test("gates on the manage_sources permission", () => {
  assert.match(src, /useHasPermission/)
  assert.match(src, /manage_sources/)
})

test("returns null when the finding has no assetId", () => {
  assert.match(src, /finding\.assetId/)
  assert.match(src, /return null/)
})

test("builds the input with asset_id plus a rule_id or path_glob scope", () => {
  assert.match(src, /asset_id/)
  assert.match(src, /rule_id/)
  assert.match(src, /path_glob/)
})
