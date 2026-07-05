import { test, expect } from "@playwright/test"

test.describe("Scan lifecycle", () => {
  test("start a scan shows running banner", async ({ page }) => {
    await page.goto("/secrets/dashboard")

    const scanButton = page.locator("button", { hasText: /run scan|start scan|scan now/i })

    if (await scanButton.isVisible({ timeout: 5000 })) {
      const responsePromise = page.waitForResponse(
        (res) => res.url().includes("/api/v1/secrets/runs") && res.request().method() === "POST",
        { timeout: 10_000 }
      )
      await scanButton.click()
      const response = await responsePromise

      if (response.status() === 202) {
        await expect(
          page.getByText(/queued|running|scanning/i)
        ).toBeVisible({ timeout: 10_000 })
      }
    } else {
      test.skip()
    }
  })

  test("cancel a running scan", async ({ page }) => {
    await page.goto("/secrets/dashboard")

    const cancelButton = page.locator("button", { hasText: /cancel/i })

    if (await cancelButton.isVisible({ timeout: 3000 })) {
      const responsePromise = page.waitForResponse(
        (res) => res.url().includes("/runs/cancel"),
        { timeout: 10_000 }
      )
      await cancelButton.click()
      await responsePromise

      await expect(
        page.getByText(/cancelled/i)
      ).toBeVisible({ timeout: 5000 })
    } else {
      test.skip()
    }
  })
})
