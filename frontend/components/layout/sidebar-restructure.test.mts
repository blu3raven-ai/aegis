import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

const ROOT = join(import.meta.dirname, "../..")
const sidebar = readFileSync(join(ROOT, "components/layout/SidebarContent.tsx"), "utf8")

describe("Sidebar — IA: Overview / Reporting / Configuration / Data", () => {
  it("renders four groups", () => {
    assert.ok(sidebar.includes('label="Overview"'), "Overview group present")
    assert.ok(sidebar.includes('label="Reporting"'), "Reporting group present")
    assert.ok(sidebar.includes('label="Configuration"'), "Configuration group present")
    assert.ok(sidebar.includes('label="Data"'), "Data group present")
  })

  it("removes the prior Dashboards / Work / Scanners / Library group labels", () => {
    assert.ok(!sidebar.includes('label="Dashboards"'), "Dashboards group label gone")
    assert.ok(!sidebar.includes('label="Work"'), "Work group label gone")
    assert.ok(!sidebar.includes('label="Scanners"'), "Scanners group label gone")
    assert.ok(!sidebar.includes('label="Library"'), "Library group label gone")
  })

  it("Overview group contains Home, Inbox, Findings, Posture in order (Activity intentionally hidden — reached via notification bell)", () => {
    const block = sidebar.match(/overviewItems[\s\S]*?\];/m)?.[0] ?? ""
    assert.ok(block.length > 0, "overviewItems array present")
    const expected = ["Home", "Inbox", "Findings", "Posture"]
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

  it("Configuration group contains Integrations and Rules", () => {
    const cfgRegex = /configurationItems[\s\S]*?\];/m
    const block = sidebar.match(cfgRegex)?.[0] ?? ""
    assert.ok(block.length > 0, "configurationItems array present")
    assert.ok(block.includes('label: "Integrations"'), "Configuration missing item: Integrations")
    assert.ok(block.includes('label: "Rules"'), "Configuration missing item: Rules")
  })

  it("Data group contains Repositories, Images, Chains (Findings lives under Overview, Releases is reached via /repos/[repoId])", () => {
    const dataRegex = /dataItems[\s\S]*?\];/m
    const block = sidebar.match(dataRegex)?.[0] ?? ""
    assert.ok(block.length > 0, "dataItems array present")
    for (const label of ["Repositories", "Images", "Chains"]) {
      assert.ok(block.includes(`label: "${label}"`), `Data missing item: ${label}`)
    }
    assert.ok(!block.includes('label: "Findings"'), "Findings should not appear in Data (lives under Overview)")
    assert.ok(!block.includes('label: "Releases"'), "Releases should not appear in Data (reached via /repos/[repoId])")
  })

  it("removes scanner-led items from the sidebar", () => {
    assert.ok(!sidebar.includes('label: "Dependencies"'), "Dependencies removed from sidebar")
    assert.ok(!sidebar.includes('label: "Containers"'), "Containers removed from sidebar")
    assert.ok(!sidebar.includes('label: "Code"'), "Code removed from sidebar")
    assert.ok(!sidebar.includes('label: "Secrets"'), "Secrets removed from sidebar")
    assert.ok(!sidebar.includes('label: "IaC Security"'), "IaC Security removed from sidebar")
    assert.ok(!sidebar.includes('label: "SBOM"'), "SBOM removed from sidebar")
    assert.ok(!sidebar.includes('label: "Sources"'), "Sources removed from sidebar")
  })

  it("wires new routes to the right hrefs", () => {
    assert.ok(sidebar.includes('href: "/"'), "Home href present")
    assert.ok(sidebar.includes('href: "/inbox"'), "Inbox href present")
    assert.ok(sidebar.includes('href: "/posture"'), "Posture href present")
    assert.ok(sidebar.includes('href: "/compliance"'), "Compliance href present")
    assert.ok(sidebar.includes('href: "/reports"'), "Reports href present")
    assert.ok(sidebar.includes('href: "/integrations"'), "Integrations href present")
    assert.ok(sidebar.includes('href: "/rules"'), "Rules href present")
    assert.ok(sidebar.includes('href: "/repos"'), "Repositories href present")
    assert.ok(sidebar.includes('href: "/images"'), "Images href present")
    assert.ok(sidebar.includes('href: "/findings"'), "Findings href present")
    assert.ok(sidebar.includes('href: "/chains"'), "Chains href present")
    // Activity intentionally absent — reachable via the notification bell only.
    assert.ok(!sidebar.includes('href: "/activity"'), "Activity href intentionally absent from sidebar")
  })

  it("highlights Repositories on the legacy /sources/{category}/[id] connection detail routes", () => {
    // The standalone /sources index page was removed when the Add Connection
    // modal moved in-place to /repos and /images, but the per-connection
    // detail routes still live under /sources/* — the sidebar item should
    // stay active there so users don't lose their place in the IA.
    assert.ok(
      sidebar.includes('pathname.startsWith("/sources/")'),
      "isActive should match /sources/* for Repositories item",
    )
  })

  it("does not special-case /operations in isActive (dead after operations/page.tsx was deleted)", () => {
    // /operations/page.tsx was deleted in Phase 5 Task 1 — the special-case is no longer needed
    assert.ok(!sidebar.includes('pathname === "/operations"'), "no /operations special-case in isActive")
    assert.ok(!sidebar.includes('pathname.startsWith("/operations")'), "no /operations prefix special-case in isActive")
  })

  it("preserves the existing brand, search, tier card, user menu, no visual changes", () => {
    assert.ok(sidebar.includes("Raven Protocol"), "Raven Protocol eyebrow preserved")
    assert.ok(sidebar.includes("Blu3Raven"), "Blu3Raven name preserved")
    assert.ok(sidebar.includes("Aegis — Vulnerability Management Portal"), "Aegis subtitle preserved")
    assert.ok(sidebar.includes("--font-space-grotesk"), "Space Grotesk font preserved")
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
    ])
    const tokens = new Set(sidebar.match(/--color-[a-z-]+/g) ?? [])
    for (const tok of tokens) {
      assert.ok(allowed.has(tok), `unexpected token ${tok} — extend the allow-list intentionally`)
    }
  })
})
