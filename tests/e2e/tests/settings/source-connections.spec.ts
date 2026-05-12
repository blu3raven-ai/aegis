import { test, expect } from "@playwright/test"
import { mockCurrentUser } from "../../fixtures/mock-api"

test.describe("Source connections settings", () => {
  test.beforeEach(async ({ page }) => {
    await mockCurrentUser(page)
    await page.route("**/settings/api/sources**", (route) =>
      route.fulfill({
        json: {
          connections: [
            { id: "conn-1", type: "github", organization: "acme-corp", status: "active" },
          ],
        },
      })
    )
  })

  test("source connections page loads", async ({ page }) => {
    await page.goto("/settings/sources")
    await expect(page.getByText(/source/i)).toBeVisible({ timeout: 5000 })
  })
})
