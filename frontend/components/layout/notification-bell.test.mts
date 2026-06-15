import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const src = readFileSync(join(ROOT, "components/layout/NotificationBell.tsx"), "utf8")
const drawer = readFileSync(join(ROOT, "components/layout/NotificationDrawer.tsx"), "utf8")
const notifBody = readFileSync(join(ROOT, "components/layout/NotificationsTabBody.tsx"), "utf8")
const activityBody = readFileSync(join(ROOT, "components/shared/activity/ActivityTabBody.tsx"), "utf8")

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
  it("renders both tab bodies as the drawer's content", () => {
    assert.ok(drawer.includes("NotificationsTabBody"), "renders NotificationsTabBody for Notifications tab")
    assert.ok(drawer.includes("ActivityTabBody"), "renders ActivityTabBody for Activity tab")
  })
  it("does not link to /notifications (the drawer is the only notifications surface)", () => {
    assert.ok(!drawer.includes('href="/notifications"'), "should not link to the deleted /notifications page")
  })
  it("supports Escape and outside-click dismiss", () => {
    assert.ok(drawer.includes("Escape"), "should dismiss on Escape")
    assert.ok(drawer.includes("mousedown"), "should dismiss on outside click")
  })
  it("delegates fetching to the tab bodies — no inline fetchNotifications or listActivity in drawer", () => {
    assert.ok(!drawer.includes("fetchNotifications"), "drawer should not call fetchNotifications directly")
    assert.ok(!drawer.includes("listActivity"), "drawer should not call listActivity directly")
  })
})

describe("Drawer Activity tab body — peek surface for the /activity page", () => {
  it("composes the shared catch-up, chips, and feed", () => {
    assert.ok(activityBody.includes("CatchUpBanner"), "renders CatchUpBanner")
    assert.ok(activityBody.includes("QuickFilterChips"), "renders QuickFilterChips")
    assert.ok(activityBody.includes("ActivityFeed"), "renders ActivityFeed")
  })
  it("retains the deep-link to /activity for the full-page audit view", () => {
    assert.ok(activityBody.includes('href="/activity"'), "should provide deep-link to /activity")
  })
})

describe("Drawer Notifications tab body — supports browsing older notifications", () => {
  it("renders a Load older affordance for pagination", () => {
    assert.ok(notifBody.includes("Load older"), "Load older button present")
  })
  it("uses fetchNotifications with limit + offset", () => {
    assert.ok(notifBody.includes("fetchNotifications"), "calls fetchNotifications")
    assert.ok(notifBody.includes("offset"), "tracks offset for pagination")
  })
})
