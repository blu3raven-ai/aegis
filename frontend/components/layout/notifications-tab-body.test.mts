import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

const src = readFileSync(
  new URL("./NotificationsTabBody.tsx", import.meta.url).pathname,
  "utf-8",
)

describe("NotificationsTabBody", () => {
  it("is a client component", () => {
    assert.ok(src.startsWith('"use client"'))
  })

  it("exports NotificationsTabBody with onNavigate prop", () => {
    assert.match(src, /export\s+function\s+NotificationsTabBody/)
    assert.match(src, /onNavigate:\s*\(\)\s*=>\s*void/)
  })

  it("uses fetchNotifications with limit + offset", () => {
    assert.match(src, /from\s+"@\/lib\/client\/notifications-api"/)
    assert.ok(src.includes("fetchNotifications"), "calls fetchNotifications")
    assert.ok(src.includes("offset"), "tracks offset")
    assert.ok(src.includes("limit"), "passes limit")
  })

  it("calls markNotificationRead and refreshNotificationCount", () => {
    assert.ok(src.includes("markNotificationRead"), "marks read on click")
    assert.ok(src.includes("refreshNotificationCount"), "refreshes the bell count")
  })

  it("renders a Load older button driven by hasMore", () => {
    assert.ok(src.includes("Load older"), "load-older button present")
  })

  it("renders an empty state when there are no notifications", () => {
    assert.ok(src.includes("No notifications"), "empty state copy preserved")
  })

  it("renders Mark all read when there are unread items", () => {
    assert.ok(src.includes("Mark all read"), "mark-all-read affordance present")
  })

  it("calls onNavigate when a notification link is followed", () => {
    assert.ok(src.includes("onNavigate"), "calls onNavigate on click")
  })
})
