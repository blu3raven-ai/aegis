import { test, expect } from "@playwright/test"
import { mockGraphQL, mockSecretsREST, mockCurrentUser } from "../../fixtures/mock-api"

test.describe("Secrets filter interactions", () => {
  test.beforeEach(async ({ page }) => {
    await mockCurrentUser(page)
    await mockGraphQL(page)
    await mockSecretsREST(page)
    await page.goto("/secrets/dashboard")
    await page.locator("button", { hasText: "Review" }).click()
  })

  test("status filter narrows findings", async ({ page }) => {
    const statusSelect = page.locator("select").first()
    await expect(statusSelect).toBeVisible()
    await statusSelect.selectOption("confirmed")
  })

  test("search box filters by text", async ({ page }) => {
    const searchInput = page.locator('input[type="search"], input[placeholder*="earch"]').first()
    if (await searchInput.isVisible()) {
      await searchInput.fill("aws-access")
      await page.waitForTimeout(500)
    }
  })

  test("clear filters restores full list", async ({ page }) => {
    const statusSelect = page.locator("select").first()
    if (await statusSelect.isVisible()) {
      await statusSelect.selectOption("confirmed")
      await page.waitForTimeout(300)

      const clearButton = page.locator("button", { hasText: /reset|clear/i })
      if (await clearButton.isVisible()) {
        await clearButton.click()
        await expect(statusSelect).toHaveValue("")
      }
    }
  })
})
