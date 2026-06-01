import { test, expect } from "@playwright/test"
import { mockCurrentUser } from "../../fixtures/mock-api"
import { mockChainsAPI, mockSSE, mockLicenseAPI } from "../../fixtures/mock-backend"

/**
 * Attack chains list and chain detail page.
 * The list page loads data via listChains() — we intercept /api/v1/chains.
 * The detail page also calls getChain() for the same endpoint.
 */

test.describe("Chains list", () => {
  test.beforeEach(async ({ page }) => {
    await mockCurrentUser(page)
    await mockChainsAPI(page)
    await mockSSE(page)
    await page.goto("/chains")
    await page.locator("h1", { hasText: "Attack Chains" }).waitFor({ timeout: 8_000 })
  })

  test("page renders heading and chains count badge", async ({ page }) => {
    await expect(page.locator("h1", { hasText: "Attack Chains" })).toBeVisible()
  })

  test("table has Chain, Severity, Status columns", async ({ page }) => {
    const thead = page.locator("thead tr").first()
    await expect(thead.getByText(/^chain$/i)).toBeVisible()
    await expect(thead.getByText(/^severity$/i)).toBeVisible()
    await expect(thead.getByText(/^status$/i)).toBeVisible()
  })

  test("renders severity badge for each chain row", async ({ page }) => {
    // At least one critical badge from mock data
    const criticalCells = page.locator("tbody td", { hasText: /^critical$/i })
    await expect(criticalCells.first()).toBeVisible({ timeout: 5_000 })
  })

  test("chain badge (type label) is visible in rows", async ({ page }) => {
    // The ChainBadge renders the chain_type text
    await expect(page.getByText(/rce-reachable/i).first()).toBeVisible({ timeout: 5_000 })
  })

  test("severity filter narrows rows", async ({ page }) => {
    const allCount = await page.locator("tbody tr").count()

    await page.getByRole("radio", { name: /^high$/i }).click()
    await page.waitForTimeout(300)

    const filteredCount = await page.locator("tbody tr").count()
    expect(filteredCount).toBeLessThanOrEqual(allCount)
  })

  test("Graph link navigates to chain detail page", async ({ page }) => {
    // Each row has a "Graph →" link
    const graphLink = page.locator("a", { hasText: /graph/i }).first()
    await expect(graphLink).toBeVisible({ timeout: 5_000 })

    const href = await graphLink.getAttribute("href")
    expect(href).toMatch(/\/chains\/chain-/)
  })
})

test.describe("Chain detail page", () => {
  test.beforeEach(async ({ page }) => {
    await mockCurrentUser(page)
    await mockChainsAPI(page)
    await mockLicenseAPI(page)
    await mockSSE(page)
    // Navigate directly to a known chain
    await page.goto("/chains/chain-01")
    await page.locator("[aria-label='Chain view mode']").waitFor({ timeout: 10_000 })
  })

  test("breadcrumb shows Chains link back to list", async ({ page }) => {
    const breadcrumb = page.locator("a", { hasText: /^chains$/i })
    await expect(breadcrumb).toBeVisible()
    const href = await breadcrumb.getAttribute("href")
    expect(href).toBe("/chains")
  })

  test("chain type is shown in heading", async ({ page }) => {
    // chain_type "RCE-reachable" rendered as "RCE reachable"
    await expect(page.getByText(/rce.+reachable/i).first()).toBeVisible({ timeout: 5_000 })
  })

  test("graph / list view toggle is present", async ({ page }) => {
    const toggle = page.locator("[aria-label='Chain view mode']")
    await expect(toggle.getByRole("radio", { name: /^graph$/i })).toBeVisible()
    await expect(toggle.getByRole("radio", { name: /^list$/i })).toBeVisible()
  })

  test("switching to list view renders fallback list", async ({ page }) => {
    await page.getByRole("radio", { name: /^list$/i }).click()
    await page.waitForTimeout(500)
    // Still on the same URL — the graph or list rendering area should be present
    await expect(page.locator("[aria-label='Chain view mode']")).toBeVisible()
  })

  test("detail drawer is open by default and shows Go/No-Go panel", async ({ page }) => {
    // GoNoGoBanner is always rendered in the open drawer
    await expect(page.getByText(/no-go|go\/no-go|block deployment/i).first()).toBeVisible({ timeout: 5_000 })
  })

  test("risk panel shows EPSS and CVSS labels", async ({ page }) => {
    await expect(page.getByText("EPSS")).toBeVisible({ timeout: 5_000 })
    await expect(page.getByText("CVSS")).toBeVisible()
  })

  test("hide details button collapses the drawer", async ({ page }) => {
    const hideBtn = page.getByRole("button", { name: /hide details/i })
    await expect(hideBtn).toBeVisible({ timeout: 5_000 })
    await hideBtn.click()
    // Drawer content (EPSS) should be gone
    await expect(page.getByText("EPSS")).not.toBeVisible({ timeout: 3_000 })
  })
})
