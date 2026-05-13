import { test, expect } from "@playwright/test"
import { mockGraphQL, mockSecretsREST, mockCurrentUser } from "../../fixtures/mock-api"

test.describe("Dashboard tab switching", () => {
  test.beforeEach(async ({ page }) => {
    await mockCurrentUser(page)
    await mockGraphQL(page)
    await mockSecretsREST(page)
  })

  test("Secrets dashboard switches between all tabs", async ({ page }) => {
    await page.goto("/secrets/dashboard")
    await expect(page.locator("button", { hasText: "Overview" })).toBeVisible()

    await page.locator("button", { hasText: "Review" }).click()
    await expect(page.locator("button", { hasText: "Review" })).toHaveClass(/text-white/)

    await page.locator("button", { hasText: "Insights" }).click()
    await expect(page.locator("button", { hasText: "Insights" })).toHaveClass(/text-white/)

    await page.locator("button", { hasText: "Health" }).click()
    await expect(page.locator("button", { hasText: "Health" })).toHaveClass(/text-white/)

    await page.locator("button", { hasText: "Settings" }).click()
    await expect(page.locator("button", { hasText: "Settings" })).toHaveClass(/text-white/)
  })

  test("Dependencies dashboard loads overview tab", async ({ page }) => {
    await page.goto("/dependencies/dashboard")
    await expect(page.locator("button", { hasText: "Overview" })).toBeVisible()
  })

  test("Code dashboard loads overview tab", async ({ page }) => {
    await page.goto("/code/dashboard")
    await expect(page.locator("button", { hasText: "Overview" })).toBeVisible()
  })

  test("Containers dashboard loads overview tab", async ({ page }) => {
    await page.goto("/containers/dashboard")
    await expect(page.locator("button", { hasText: "Overview" })).toBeVisible()
  })
})
