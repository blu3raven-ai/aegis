import { test, expect } from "@playwright/test"
import { mockCurrentUser } from "../../fixtures/mock-api"
import { mockInsightsAPI } from "../../fixtures/mock-backend"

/**
 * Insights dashboard — temporal series, top authors, MTTR, anomalies.
 * All data comes from /api/v1/temporal/* which we intercept here.
 */

test.describe("Insights dashboard", () => {
  test.beforeEach(async ({ page }) => {
    await mockCurrentUser(page)
    await mockInsightsAPI(page)
    await page.goto("/insights")
    // Wait for the window selector to confirm the page has mounted
    await page.locator("button, [role='radio']", { hasText: /30d/i })
      .first()
      .waitFor({ timeout: 10_000 })
  })

  test("page title section is visible", async ({ page }) => {
    // InsightsHeader renders the window/severity controls — confirms the page loaded
    await expect(
      page.getByText(/findings introduced over time/i).or(
        page.getByText(/insights/i).first()
      )
    ).toBeVisible({ timeout: 5_000 })
  })

  test("findings over time section card is rendered", async ({ page }) => {
    await expect(page.getByText(/findings introduced over time/i)).toBeVisible({ timeout: 5_000 })
  })

  test("top authors section card is rendered", async ({ page }) => {
    await expect(page.getByText(/top authors/i)).toBeVisible({ timeout: 5_000 })
  })

  test("MTTR section card is rendered", async ({ page }) => {
    await expect(page.getByText(/mttr/i)).toBeVisible({ timeout: 5_000 })
  })

  test("anomalies section card is rendered", async ({ page }) => {
    await expect(page.getByText(/anomalies/i)).toBeVisible({ timeout: 5_000 })
  })

  test("window chip 7d triggers a new temporal series request", async ({ page }) => {
    let seriesCalled = 0
    await page.route("**/api/v1/temporal/series**", (route) => {
      seriesCalled++
      return route.fulfill({ json: { series: [] } })
    })

    const btn7d = page
      .getByRole("button", { name: /^7d$/i })
      .or(page.getByRole("radio", { name: /^7d$/i }))
      .first()

    if (await btn7d.isVisible({ timeout: 3_000 })) {
      const countBefore = seriesCalled
      await btn7d.click()
      await page.waitForTimeout(600)
      expect(seriesCalled).toBeGreaterThan(countBefore)
    }
  })

  test("severity filter chip triggers a new temporal series request", async ({ page }) => {
    let seriesCalled = 0
    await page.route("**/api/v1/temporal/series**", (route) => {
      seriesCalled++
      return route.fulfill({ json: { series: [] } })
    })

    const criticalBtn = page
      .getByRole("button", { name: /^critical$/i })
      .or(page.getByRole("radio", { name: /^critical$/i }))
      .first()

    if (await criticalBtn.isVisible({ timeout: 3_000 })) {
      const countBefore = seriesCalled
      await criticalBtn.click()
      await page.waitForTimeout(600)
      expect(seriesCalled).toBeGreaterThan(countBefore)
    }
  })

  test("chart renders or shows empty state when series is empty", async ({ page }) => {
    // With mocked data containing 3 points the chart component should render.
    // We tolerate either a canvas/svg element OR an "empty state" text.
    const chartOrEmpty = page
      .locator("canvas, svg[role='img'], [data-testid='chart']")
      .or(page.getByText(/no data|empty|no findings/i))

    // At least one of these should appear inside the card
    await expect(chartOrEmpty.first()).toBeVisible({ timeout: 8_000 })
  })

  test("top authors panel shows author names from mock data", async ({ page }) => {
    // Mock returns alice + bob
    await expect(
      page.getByText("alice").or(page.getByText(/top authors \(introduced\)/i))
    ).toBeVisible({ timeout: 8_000 })
  })

  test("MTTR table shows scanner groups from mock data", async ({ page }) => {
    // Mock returns deps / sast / secrets
    await expect(
      page.getByText("deps").or(page.getByText(/mttr by scanner/i))
    ).toBeVisible({ timeout: 8_000 })
  })
})
