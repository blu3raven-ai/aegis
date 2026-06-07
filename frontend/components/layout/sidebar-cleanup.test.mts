import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const sidebar = readFileSync(join(ROOT, "components/layout/SidebarContent.tsx"), "utf8")
const shell = readFileSync(join(ROOT, "app/(app)/AppShell.tsx"), "utf8")

describe("Sidebar and AppShell cleanup", () => {
  it("SidebarContent does not have notificationCount prop", () => {
    assert.ok(!sidebar.includes("notificationCount"), "should not have notificationCount")
  })
  it("SidebarContent does not have notifications footer link", () => {
    assert.ok(!sidebar.includes('href="/notifications"'), "should not have /notifications link in sidebar")
  })
  it("SidebarContent does not have Help & Support link", () => {
    assert.ok(!sidebar.includes('href="/help"'), "should not have /help link")
  })
  it("AppShell does not call useNotificationCount", () => {
    assert.ok(!shell.includes("useNotificationCount"), "AppShell should not call useNotificationCount")
  })
  it("AppShell does not pass notificationCount prop", () => {
    assert.ok(!shell.includes("notificationCount"), "AppShell should not pass notificationCount")
  })
})
