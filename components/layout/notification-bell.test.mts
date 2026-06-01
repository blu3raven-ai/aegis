import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "components/layout/NotificationBell.tsx"), "utf8")
const drawer = readFileSync(join(ROOT, "components/layout/NotificationDrawer.tsx"), "utf8")

describe("NotificationBell", () => {
  it("opens a drawer rather than navigating to /notifications", () => {
    assert.ok(src.includes("NotificationDrawer"), "should render NotificationDrawer")
    assert.ok(!src.includes('href="/notifications"'), "should not navigate to /notifications via Link")
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

describe("NotificationDrawer", () => {
  it("renders an Activity tab using the existing ActivityFeed component", () => {
    assert.ok(drawer.includes("ActivityFeed"), "should reuse ActivityFeed for activity tab")
  })
  it("links to /activity for deep-link compat", () => {
    assert.ok(drawer.includes('href="/activity"'), "should provide deep-link to /activity")
  })
  it("links to /notifications for deep-link compat", () => {
    assert.ok(drawer.includes('href="/notifications"'), "should provide deep-link to /notifications")
  })
  it("supports Escape and outside-click dismiss", () => {
    assert.ok(drawer.includes("Escape"), "should dismiss on Escape")
    assert.ok(drawer.includes("mousedown"), "should dismiss on outside click")
  })
})
