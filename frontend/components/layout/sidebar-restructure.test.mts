import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const sidebar = readFileSync(join(ROOT, "components/layout/SidebarContent.tsx"), "utf8")

describe("Sidebar — IA: Overview / Workspace / Inventory / Reporting / Configure", () => {
  it("renders all five group labels", () => {
    assert.ok(sidebar.includes('label="Overview"'), "Overview group label present")
    assert.ok(sidebar.includes('label="Workspace"'), "Workspace group label present")
    assert.ok(sidebar.includes('label="Inventory"'), "Inventory group label present")
    assert.ok(sidebar.includes('label="Reporting"'), "Reporting group label present")
    assert.ok(sidebar.includes('label="Configure"'), "Configure group label present")
    assert.ok(!sidebar.includes('label="Configuration"'), "Tail group is labelled Configure, not Configuration")
    assert.ok(!sidebar.includes('label="Insights"'), "Insights group renamed to Reporting (Insights is now the Overview page)")
    assert.ok(!sidebar.includes('label="Data"'), "Data renamed to Inventory (ASPM-standard term)")
  })

  it("removes the prior Dashboards / Work / Scanners / Library group labels", () => {
    assert.ok(!sidebar.includes('label="Dashboards"'), "Dashboards group label gone")
    assert.ok(!sidebar.includes('label="Work"'), "Work group label gone")
    assert.ok(!sidebar.includes('label="Scanners"'), "Scanners group label gone")
    assert.ok(!sidebar.includes('label="Library"'), "Library group label gone")
  })

  it("Overview section contains Home, Inbox, Findings, Insights in order (Activity intentionally hidden — reached via notification bell)", () => {
    const block = sidebar.match(/overviewItems[\s\S]*?\];/m)?.[0] ?? ""
    assert.ok(block.length > 0, "overviewItems array present")
    const expected = ["Home", "Inbox", "Findings", "Insights"]
    for (const label of expected) {
      assert.ok(block.includes(`label: "${label}"`), `Overview missing item: ${label}`)
    }
    for (let i = 0; i < expected.length - 1; i++) {
      const a = block.indexOf(`label: "${expected[i]}"`)
      const b = block.indexOf(`label: "${expected[i + 1]}"`)
      assert.ok(a < b, `Overview item "${expected[i]}" must precede "${expected[i + 1]}"`)
    }
    assert.ok(!block.includes('label: "Activity"'), "Activity should not appear in sidebar (notification-bell only)")
  })

  it("Reporting group contains Compliance and Reports", () => {
    const block = sidebar.match(/reportingItems[\s\S]*?\];/m)?.[0] ?? ""
    assert.ok(block.length > 0, "reportingItems array present")
    for (const label of ["Compliance", "Reports"]) {
      assert.ok(block.includes(`label: "${label}"`), `Reporting missing item: ${label}`)
    }
  })

  it("Configuration section contains Policies, Integrations, Notifications — Rules renamed to Policies per peer vocabulary", () => {
    const cfgRegex = /configurationItems[\s\S]*?\];/m
    const block = sidebar.match(cfgRegex)?.[0] ?? ""
    assert.ok(block.length > 0, "configurationItems array present")
    assert.ok(block.includes('label: "Policies"'), "Configuration missing item: Policies")
    assert.ok(block.includes('label: "Integrations"'), "Configuration missing item: Integrations")
    assert.ok(block.includes('label: "Notifications"'), "Configuration missing item: Notifications")
    assert.ok(!block.includes('label: "Rules"'), "Rules renamed to Policies")
  })

  it("Inventory group contains Sources, SBOM and Chains (Images unified into /sources, Findings lives under Overview, Releases is reached via /sources/[id])", () => {
    const dataRegex = /dataItems[\s\S]*?\];/m
    const block = sidebar.match(dataRegex)?.[0] ?? ""
    assert.ok(block.length > 0, "dataItems array present")
    for (const label of ["Sources", "SBOM", "Chains"]) {
      assert.ok(block.includes(`label: "${label}"`), `Inventory missing item: ${label}`)
    }
    assert.ok(!block.includes('label: "Images"'), "Images should not appear in Inventory (unified into /sources)")
    assert.ok(!block.includes('label: "Findings"'), "Findings should not appear in Inventory (lives under Overview)")
    assert.ok(!block.includes('label: "Releases"'), "Releases should not appear in Inventory (reached via /sources/[id])")
  })

  it("removes scanner-led items from the sidebar", () => {
    assert.ok(!sidebar.includes('label: "Dependencies"'), "Dependencies removed from sidebar")
    assert.ok(!sidebar.includes('label: "Containers"'), "Containers removed from sidebar")
    assert.ok(!sidebar.includes('label: "Code"'), "Code removed from sidebar")
    assert.ok(!sidebar.includes('label: "Secrets"'), "Secrets removed from sidebar")
    assert.ok(!sidebar.includes('label: "IaC Security"'), "IaC Security removed from sidebar")
  })

  it("wires new routes to the right hrefs", () => {
    assert.ok(sidebar.includes('href: "/"'), "Home href present")
    assert.ok(sidebar.includes('href: "/inbox"'), "Inbox href present")
    assert.ok(sidebar.includes('href: "/insights"'), "Insights href present")
    assert.ok(sidebar.includes('href: "/compliance"'), "Compliance href present")
    assert.ok(sidebar.includes('href: "/reports"'), "Reports href present")
    assert.ok(sidebar.includes('href: "/integrations"'), "Integrations href present")
    assert.ok(sidebar.includes('href: "/policies"'), "Policies href present")
    assert.ok(sidebar.includes('href: "/sources"'), "Sources href present")
    assert.ok(sidebar.includes('href: "/sbom"'), "SBOM href present")
    assert.ok(!sidebar.includes('href: "/images"'), "Images href should be absent — unified into /sources")
    assert.ok(sidebar.includes('href: "/findings"'), "Findings href present")
    assert.ok(sidebar.includes('href: "/chains"'), "Chains href present")
    // Activity intentionally absent — reachable via the notification bell only.
    assert.ok(!sidebar.includes('href: "/activity"'), "Activity href intentionally absent from sidebar")
  })

  it("does not special-case /operations in isActive (dead after operations/page.tsx was deleted)", () => {
    // /operations/page.tsx was deleted in Phase 5 Task 1 — the special-case is no longer needed
    assert.ok(!sidebar.includes('pathname === "/operations"'), "no /operations special-case in isActive")
    assert.ok(!sidebar.includes('pathname.startsWith("/operations")'), "no /operations prefix special-case in isActive")
  })

  it("preserves the existing brand, search, tier card, user menu, no visual changes", () => {
    // Branding flows through useBranding(). Vendor (NULL name) shows the
    // hardcoded 3-line identity; customer (any non-null name) shows only
    // [logo] {name} — no subtitle line.
    assert.ok(sidebar.includes("useBranding()"), "useBranding hook is wired")
    assert.ok(sidebar.includes("{brandName}"), "brand name renders from hook")
    assert.ok(!sidebar.includes("brandSubtitle"), "no subtitle wiring — customer layout is single-line")
    assert.ok(sidebar.includes("font-mono"), "branding renders in the mono font")
    assert.ok(sidebar.includes("UserMenuButton"), "UserMenuButton preserved")
    assert.ok(sidebar.includes("TIER_LABELS[tier]"), "Tier card preserved")
  })

  it("does not introduce any unexpected design tokens", () => {
    // Snapshot allow-list of tokens used by SidebarContent. The severity-critical
    // pair was added when the Inbox nav-item picked up the mock's danger-tone
    // count badge — extend this list when adding intentional new tokens.
    const allowed = new Set([
      "--color-border",
      "--color-surface",
      "--color-surface-raised",
      "--color-text-primary",
      "--color-text-secondary",
      "--color-accent",
      "--color-accent-subtle",
      "--color-nav-active",
      "--color-bg",
      "--color-state-dismissed",
      "--color-state-dismissed-border",
      "--color-state-dismissed-subtle",
      "--color-severity-critical",
      "--color-severity-critical-subtle",
      "--color-severity-critical-text",
    ])
    const tokens = new Set(sidebar.match(/--color-[a-z-]+/g) ?? [])
    for (const tok of tokens) {
      assert.ok(allowed.has(tok), `unexpected token ${tok} — extend the allow-list intentionally`)
    }
  })
})
