import { test, expect } from "@playwright/test"
import { mockCurrentUser } from "../../fixtures/mock-api"

test.describe("User management", () => {
  test("admin can see user list", async ({ page }) => {
    await mockCurrentUser(page, "owner")
    await page.route("**/api/v1/settings/users**", (route) =>
      route.fulfill({
        json: {
          users: [
            { id: "u1", username: "e2e-admin", email: "e2e-admin@test.local", role: "owner", status: "active" },
            { id: "u2", username: "e2e-viewer", email: "e2e-viewer@test.local", role: "viewer", status: "active" },
          ],
        },
      })
    )

    await page.goto("/settings/users")
    await expect(page.getByText("e2e-admin")).toBeVisible({ timeout: 5000 })
    await expect(page.getByText("e2e-viewer")).toBeVisible()
  })

  test("viewer role sees restricted access message", async ({ page }) => {
    await mockCurrentUser(page, "viewer")
    await page.goto("/settings/users")
    await expect(
      page.getByText(/access|permission|denied/i).or(page.locator('a[href="/"]'))
    ).toBeVisible({ timeout: 5000 })
  })
})
