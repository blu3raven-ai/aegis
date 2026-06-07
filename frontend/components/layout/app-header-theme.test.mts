import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "components/layout/AppHeader.tsx"), "utf8")

describe("AppHeader — theme toggle integration", () => {
  it("imports ThemeToggleButton", () => {
    assert.ok(src.includes("ThemeToggleButton"), "should import ThemeToggleButton")
  })

  it("does not import UserMenuButton", () => {
    assert.ok(!src.includes("UserMenuButton"), "should not import UserMenuButton")
  })

  it("renders ThemeToggleButton", () => {
    assert.ok(src.includes("<ThemeToggleButton"), "should render ThemeToggleButton")
  })

  it("does not render UserMenuButton", () => {
    assert.ok(!src.includes("<UserMenuButton"), "should not render UserMenuButton")
  })
})
