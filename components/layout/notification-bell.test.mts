import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "components/layout/NotificationBell.tsx"), "utf8")

describe("NotificationBell", () => {
  it("links to /notifications", () => {
    assert.ok(src.includes('href="/notifications"'), "should link to /notifications")
  })
  it("has aria-label mentioning unread count", () => {
    assert.ok(src.includes("aria-label"), "should have aria-label")
    assert.ok(src.includes("unread"), "aria-label should mention unread count")
  })
  it("caps badge at 99+", () => {
    assert.ok(src.includes("99+"), "should cap badge display at 99+")
  })
  it("badge is absolutely positioned to avoid layout shift", () => {
    assert.ok(src.includes("absolute"), "badge should be absolute positioned")
  })
  it("uses useNotificationCount hook", () => {
    assert.ok(src.includes("useNotificationCount"), "should use useNotificationCount hook")
  })
})
