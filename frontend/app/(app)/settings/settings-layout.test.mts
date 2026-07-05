import { readFileSync } from "node:fs"
import assert from "node:assert/strict"
import test from "node:test"

const source = readFileSync(new URL("./layout.tsx", import.meta.url), "utf8")

test("settings layout no longer renders SidebarNav", () => {
  assert.doesNotMatch(source, /SidebarNav/)
})

test("settings layout passes children through", () => {
  assert.match(source, /\{children\}/)
})

test("settings layout has no server-side session check", () => {
  assert.doesNotMatch(source, /getSession/)
  assert.doesNotMatch(source, /getTeamCountServer/)
  assert.doesNotMatch(source, /getRoleCountServer/)
})
