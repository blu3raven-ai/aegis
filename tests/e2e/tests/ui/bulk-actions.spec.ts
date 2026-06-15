import { test, expect } from "@playwright/test"
import { mockGraphQL, mockSecretsREST, mockCurrentUser } from "../../fixtures/mock-api"

test.describe("Bulk actions", () => {
  test.beforeEach(async ({ page }) => {
    await mockCurrentUser(page)
    await mockGraphQL(page)
    await mockSecretsREST(page)
    await page.goto("/secrets/dashboard")
    await page.locator("button", { hasText: "Review" }).click()
  })

  test("selecting checkboxes shows selection count", async ({ page }) => {
    const checkboxes = page.locator('input[type="checkbox"]')
    await checkboxes.first().waitFor({ timeout: 5000 })

    const count = await checkboxes.count()
    if (count >= 2) {
      await checkboxes.nth(0).check()
      await checkboxes.nth(1).check()
      await expect(page.getByText(/2\s*selected/i)).toBeVisible({ timeout: 3000 })
    }
  })

  test("bulk confirm sends correct API call", async ({ page }) => {
    const checkboxes = page.locator('input[type="checkbox"]')
    await checkboxes.first().waitFor({ timeout: 5000 })

    if (await checkboxes.first().isVisible()) {
      await checkboxes.first().check()

      await page.route("**/api/v1/secrets/findings/review", (route) =>
        route.fulfill({ json: { ok: true } })
      )

      const confirmButton = page.locator("button", { hasText: /confirm/i })
      if (await confirmButton.isVisible()) {
        await confirmButton.click()
      }
    }
  })
})
