import { test, expect } from "@playwright/test"
import { mockCurrentUser } from "../../fixtures/mock-api"

test.describe("Organization settings", () => {
  test.beforeEach(async ({ page }) => {
    await mockCurrentUser(page)
    await page.route("**/api/v1/settings/organisations**", (route) =>
      route.fulfill({
        json: {
          organizations: [
            { name: "acme-corp", enabled: true },
          ],
        },
      })
    )
  })

  test("organizations page loads", async ({ page }) => {
    await page.goto("/settings/organisations")
    await expect(page.getByText(/acme-corp/i)).toBeVisible({ timeout: 5000 })
  })
})
