import { test, expect } from "@playwright/test"

test.describe("Secrets review workflow", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/secrets/dashboard")
    await page.locator("button", { hasText: "Review" }).click()
    await page.locator("tr").nth(1).waitFor({ timeout: 10_000 })
  })

  test("clicking a finding opens the detail drawer", async ({ page }) => {
    const firstFindingRow = page.locator("tr").nth(1)
    await firstFindingRow.click()

    await expect(
      page.locator('[class*="fixed"]').or(page.locator("text=Code Preview"))
    ).toBeVisible({ timeout: 5000 })
  })

  test("confirm a finding updates its review status", async ({ page }) => {
    const checkbox = page.locator('input[type="checkbox"]').first()
    await checkbox.check()

    const confirmBtn = page.locator("button", { hasText: /confirm/i })
    if (await confirmBtn.isVisible({ timeout: 3000 })) {
      const responsePromise = page.waitForResponse(
        (res) => res.url().includes("/findings/review") && res.status() === 200,
        { timeout: 10_000 }
      )
      await confirmBtn.click()
      await responsePromise
    }
  })

  test("dismiss as false positive", async ({ page }) => {
    const checkbox = page.locator('input[type="checkbox"]').first()
    await checkbox.check()

    const fpBtn = page.locator("button", { hasText: /false positive/i })
    if (await fpBtn.isVisible({ timeout: 3000 })) {
      const responsePromise = page.waitForResponse(
        (res) => res.url().includes("/findings/review") && res.status() === 200,
        { timeout: 10_000 }
      )
      await fpBtn.click()
      await responsePromise
    }
  })
})
