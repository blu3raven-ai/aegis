import { test, expect } from "@playwright/test"

test.use({ storageState: { cookies: [], origins: [] } })

test.describe("Login flow", () => {
  const username = process.env.E2E_USERNAME ?? "admin"
  const password = process.env.E2E_PASSWORD ?? ""

  test("valid login redirects to home", async ({ page }) => {
    await page.goto("/login")
    await page.locator('input[placeholder="you@example.com or username"]').fill(username)
    await page.locator('input[type="password"]').fill(password)
    await page.locator('button[type="submit"]').click()

    await page.waitForURL("**/", { timeout: 10_000 })
    expect(page.url()).not.toContain("/login")
  })

  test("invalid password shows error", async ({ page }) => {
    await page.goto("/login")
    await page.locator('input[placeholder="you@example.com or username"]').fill(username)
    await page.locator('input[type="password"]').fill("wrong-password-e2e-12345")
    await page.locator('button[type="submit"]').click()

    await expect(page.locator(".bg-red-50, .bg-red-900\\/30")).toBeVisible({ timeout: 5000 })
    expect(page.url()).toContain("/login")
  })

  test("logout clears session and redirects to login", async ({ page }) => {
    await page.goto("/login")
    await page.locator('input[placeholder="you@example.com or username"]').fill(username)
    await page.locator('input[type="password"]').fill(password)
    await page.locator('button[type="submit"]').click()
    await page.waitForURL("**/", { timeout: 10_000 })

    const logoutLink = page.locator("a[href*='logout'], button:has-text('Log out'), button:has-text('Sign out')")
    if (await logoutLink.isVisible({ timeout: 3000 })) {
      await logoutLink.click()
      await page.waitForURL("**/login", { timeout: 5000 })
    }
  })
})
