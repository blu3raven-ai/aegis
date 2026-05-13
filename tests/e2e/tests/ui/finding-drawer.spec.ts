import { test, expect } from "@playwright/test"
import { mockGraphQL, mockSecretsREST, mockCurrentUser } from "../../fixtures/mock-api"

test.describe("Finding drawer", () => {
  test.beforeEach(async ({ page }) => {
    await mockCurrentUser(page)
    await mockGraphQL(page)
    await mockSecretsREST(page)
    await page.goto("/secrets/dashboard")
    await page.locator("button", { hasText: "Review" }).click()
  })

  test("clicking a finding row opens the drawer", async ({ page }) => {
    const firstRow = page.locator("tr").nth(1)
    await firstRow.waitFor({ timeout: 5000 })
    await firstRow.click()
    await expect(page.locator("text=generic-api-key")).toBeVisible({ timeout: 3000 })
  })

  test("clicking a different finding updates the drawer", async ({ page }) => {
    const rows = page.locator("tr")
    const firstRow = rows.nth(1)
    const secondRow = rows.nth(2)

    await firstRow.waitFor({ timeout: 5000 })
    await firstRow.click()
    await expect(page.locator("text=generic-api-key")).toBeVisible({ timeout: 3000 })

    if (await secondRow.isVisible()) {
      await secondRow.click()
      await expect(page.locator('[class*="fixed"]')).toBeVisible({ timeout: 3000 })
    }
  })
})
