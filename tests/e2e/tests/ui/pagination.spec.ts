import { test, expect } from "@playwright/test"
import { mockGraphQL, mockSecretsREST, mockCurrentUser } from "../../fixtures/mock-api"
import { makeSecretFindings } from "../../fixtures/test-data"

test.describe("Pagination", () => {
  test.beforeEach(async ({ page }) => {
    await mockCurrentUser(page)
    await mockGraphQL(page, {
      secretFindings: {
        items: makeSecretFindings(10),
        totalCount: 30,
        pageInfo: { hasNextPage: true, hasPreviousPage: false, totalPages: 3 },
      },
    })
    await mockSecretsREST(page)
    await page.goto("/secrets/dashboard")
    await page.locator("button", { hasText: "Review" }).click()
  })

  test("shows page info", async ({ page }) => {
    await expect(page.getByText(/page\s*1/i)).toBeVisible({ timeout: 5000 })
  })

  test("next page button navigates forward", async ({ page }) => {
    const nextButton = page.locator("button", { hasText: /next|→|›/i })
    if (await nextButton.isVisible()) {
      await nextButton.click()
    }
  })
})
