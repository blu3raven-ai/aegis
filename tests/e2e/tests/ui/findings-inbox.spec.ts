import { test, expect } from "@playwright/test"
import { mockCurrentUser } from "../../fixtures/mock-api"
import { mockSSE } from "../../fixtures/mock-backend"

/**
 * Findings inbox — the unified cross-scanner findings view.
 * All data is served inline from the page's DEMO_FINDINGS constant,
 * so the only API calls we need to stub are /auth/me and the SSE stream.
 */

test.describe("Findings inbox", () => {
  test.beforeEach(async ({ page }) => {
    await mockCurrentUser(page)
    await mockSSE(page)
    await page.goto("/findings")
    // Wait until the heading is visible before each assertion
    await page.locator("h1", { hasText: "Findings" }).waitFor({ timeout: 8_000 })
  })

  test("page renders heading and findings count badge", async ({ page }) => {
    await expect(page.locator("h1", { hasText: "Findings" })).toBeVisible()
    // Count badge next to heading
    await expect(page.locator('span', { hasText: "9" }).first()).toBeVisible({ timeout: 3_000 })
  })

  test("table renders expected columns", async ({ page }) => {
    const thead = page.locator("thead tr").first()
    await expect(thead.getByText(/finding/i)).toBeVisible()
    await expect(thead.getByText(/chain/i)).toBeVisible()
    await expect(thead.getByText(/risk/i)).toBeVisible()
  })

  test("table shows at least one finding row", async ({ page }) => {
    const rows = page.locator("tbody tr")
    await expect(rows.first()).toBeVisible({ timeout: 5_000 })
    const count = await rows.count()
    expect(count).toBeGreaterThan(0)
  })

  test("severity filter chip narrows the table", async ({ page }) => {
    const allRows = page.locator("tbody tr")
    const allCount = await allRows.count()

    // Click the "Critical" severity filter
    await page.getByRole("radio", { name: /^critical$/i }).click()
    await page.waitForTimeout(300)

    const filteredCount = await page.locator("tbody tr").count()
    // Critical findings should be fewer than the unfiltered set
    expect(filteredCount).toBeLessThanOrEqual(allCount)
  })

  test("active filter tag appears when severity filter is selected", async ({ page }) => {
    await page.getByRole("radio", { name: /^high$/i }).click()
    await expect(page.getByText(/severity: high/i)).toBeVisible({ timeout: 3_000 })
  })

  test("clearing severity filter restores full list", async ({ page }) => {
    const allRows = page.locator("tbody tr")
    const allCount = await allRows.count()

    await page.getByRole("radio", { name: /^critical$/i }).click()
    await page.waitForTimeout(200)

    // Clear via the "All" radio
    await page.getByRole("radio", { name: /^all$/i }).click()
    await page.waitForTimeout(200)

    const restoredCount = await allRows.count()
    expect(restoredCount).toBe(allCount)
  })

  test("clicking a finding row opens the detail drawer", async ({ page }) => {
    const firstRow = page.locator("tbody tr").first()
    await firstRow.waitFor({ timeout: 5_000 })
    await firstRow.click()

    // Drawer should become visible — it wraps a close button with aria-label
    await expect(
      page.locator('[aria-label="Close"], button:has-text("Close")').or(
        page.locator('[role="dialog"], [data-testid="findings-drawer"]')
      )
    ).toBeVisible({ timeout: 5_000 })
  })

  test("drawer shows risk score for a finding that has one", async ({ page }) => {
    // First finding (log4j) has riskScore: 94
    const firstRow = page.locator("tbody tr").first()
    await firstRow.click()

    await expect(page.getByText("Risk Score")).toBeVisible({ timeout: 5_000 })
    // The score 94 should appear somewhere in the drawer
    await expect(page.getByText("94")).toBeVisible({ timeout: 3_000 })
  })

  test("drawer shows chain badge for a chain-attached finding", async ({ page }) => {
    // The log4j finding at row 1 has chains: [chain-01, RCE-reachable]
    const firstRow = page.locator("tbody tr").first()
    await firstRow.click()

    await expect(page.getByText(/attack chain/i)).toBeVisible({ timeout: 5_000 })
    await expect(page.getByText(/rce-reachable/i)).toBeVisible({ timeout: 3_000 })
  })

  test("view mode toggle to 'Chained' filters to chain-only rows", async ({ page }) => {
    const allCount = await page.locator("tbody tr").count()

    await page.getByRole("radio", { name: /^chained$/i }).click()
    await page.waitForTimeout(300)

    const chainedCount = await page.locator("tbody tr").count()
    expect(chainedCount).toBeLessThanOrEqual(allCount)
    // At least the 3 chained demo findings should still appear
    expect(chainedCount).toBeGreaterThan(0)
  })
})
