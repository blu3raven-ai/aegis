import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const SRC = readFileSync(new URL("./AuditCommandBar.tsx", import.meta.url), "utf8")

test("AuditCommandBar is built on the shared CommandBar", () => {
  assert.match(SRC, /from "@\/components\/shared\/command-bar"/)
  assert.match(SRC, /<CommandBar/)
})

test("AuditCommandBar exposes action + resource filters and free-text search", () => {
  assert.match(SRC, /key: "action"/)
  assert.match(SRC, /key: "resource"/)
  assert.match(SRC, /searchInput=/)
})

test("AuditCommandBar keeps the date-range segmented control", () => {
  assert.match(SRC, /SegmentedControl/)
})
