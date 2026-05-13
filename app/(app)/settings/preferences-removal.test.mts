import { readFileSync } from "node:fs"
import { test } from "node:test"
import assert from "node:assert/strict"

const sidebarNav = readFileSync(
  new URL("./SidebarNav.tsx", import.meta.url),
  "utf8"
)

test("SidebarNav does not include preferences nav item", () => {
  assert.doesNotMatch(sidebarNav, /settings\/preferences/)
})

test("SidebarNav does not import AppearanceSettings", () => {
  assert.doesNotMatch(sidebarNav, /AppearanceSettings/)
})
