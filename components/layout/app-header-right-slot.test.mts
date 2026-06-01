import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "components/layout/AppHeader.tsx"), "utf8")

describe("AppHeader right slot", () => {
  it("imports NotificationBell", () => {
    assert.ok(src.includes("NotificationBell"), "should import NotificationBell")
  })
  it("imports HeaderCTAs", () => {
    assert.ok(src.includes("HeaderCTAs"), "should import HeaderCTAs")
  })
  it("renders NotificationBell", () => {
    assert.ok(src.includes("<NotificationBell"), "should render NotificationBell")
  })
  it("renders HeaderCTAs", () => {
    assert.ok(src.includes("<HeaderCTAs"), "should render HeaderCTAs")
  })
  it("has vertical divider between pill group and icon group", () => {
    assert.ok(src.includes("h-5 w-px"), "should have vertical divider sized to match 36px icon-button row")
  })
})
