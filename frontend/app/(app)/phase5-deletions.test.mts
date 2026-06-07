import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { existsSync, readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "..", "..")

function read(rel: string): string {
  return readFileSync(join(ROOT, rel), "utf8")
}

describe("Phase 5 deletions", () => {
  it("operations/page.tsx is gone", () => {
    assert.ok(!existsSync(join(ROOT, "app/(app)/operations/page.tsx")))
  })
  it("policies/page.tsx is a redirect to /rules", () => {
    const src = read("app/(app)/policies/page.tsx")
    assert.ok(src.includes('redirect("/rules")'))
  })
  it("help/page.tsx is gone", () => {
    assert.ok(!existsSync(join(ROOT, "app/(app)/help/page.tsx")))
  })
  it("insights/page.tsx is gone", () => {
    assert.ok(!existsSync(join(ROOT, "app/(app)/insights/page.tsx")))
  })
  it("notifications/page.tsx is gone", () => {
    assert.ok(!existsSync(join(ROOT, "app/(app)/notifications/page.tsx")))
  })
})

describe("Phase 5 file move", () => {
  it("IntegrationsContent lives at integrations/", () => {
    assert.ok(existsSync(join(ROOT, "app/(app)/integrations/IntegrationsContent.tsx")))
  })
  it("IntegrationsContent no longer at operations/", () => {
    assert.ok(!existsSync(join(ROOT, "app/(app)/operations/IntegrationsContent.tsx")))
  })
})

describe("Phase 5 wiring", () => {
  it("/integrations/page.tsx renders IntegrationsContent (no redirect)", () => {
    const src = read("app/(app)/integrations/page.tsx")
    assert.ok(src.includes("IntegrationsContent"))
    assert.ok(!src.includes("redirect("))
  })
  it("sidebar Rules item targets /rules", () => {
    const src = read("components/layout/SidebarContent.tsx")
    assert.match(src, /href:\s*"\/rules",\s*label:\s*"Rules"/)
    assert.ok(!src.includes('href: "/settings/sla-policies"'))
  })
  it("sidebar isActive no longer special-cases /operations", () => {
    const src = read("components/layout/SidebarContent.tsx")
    assert.ok(!src.includes('pathname === "/operations"'))
    assert.ok(!src.includes('pathname.startsWith("/operations")'))
  })
  it("AppHeader no longer special-cases /operations breadcrumbs", () => {
    const src = read("components/layout/AppHeader.tsx")
    assert.ok(!src.includes('"/operations"'))
  })
  it("NotificationDrawer no longer links to /notifications", () => {
    const src = read("components/layout/NotificationDrawer.tsx")
    assert.ok(!src.includes('href="/notifications"'))
    assert.ok(!src.includes("View all notifications"))
  })
})
