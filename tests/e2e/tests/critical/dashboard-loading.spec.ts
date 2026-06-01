import { test, expect } from "@playwright/test"

test.describe("Dashboard loading with real data", () => {
  test("Secrets dashboard overview loads", async ({ page }) => {
    await page.goto("/secrets/dashboard")
    await expect(page.locator("button", { hasText: "Overview" })).toBeVisible({ timeout: 10_000 })
    await expect(page.locator(".bg-red-50")).not.toBeVisible({ timeout: 5000 })
  })

  test("Dependencies dashboard overview loads", async ({ page }) => {
    await page.goto("/dependencies/dashboard")
    await expect(page.locator("button", { hasText: "Overview" })).toBeVisible({ timeout: 10_000 })
  })

  test("Code dashboard overview loads", async ({ page }) => {
    await page.goto("/code/dashboard")
    await expect(page.locator("button", { hasText: "Overview" })).toBeVisible({ timeout: 10_000 })
  })

  test("Containers dashboard overview loads", async ({ page }) => {
    await page.goto("/containers/dashboard")
    await expect(page.locator("button", { hasText: "Overview" })).toBeVisible({ timeout: 10_000 })
  })

  test("Secrets Review tab shows findings", async ({ page }) => {
    await page.goto("/secrets/dashboard")
    await page.locator("button", { hasText: "Review" }).click()
    await expect(page.locator("tr").nth(1)).toBeVisible({ timeout: 10_000 })
  })

  test("Tab switching works on Secrets dashboard", async ({ page }) => {
    await page.goto("/secrets/dashboard")

    const tabs = ["Review", "Insights", "Health", "Overview"]
    for (const tab of tabs) {
      await page.locator("button", { hasText: tab }).click()
      await expect(page.locator("button", { hasText: tab })).toHaveClass(/text-\[var\(--color-accent-on\)\]/, { timeout: 5000 })
    }
  })
})
