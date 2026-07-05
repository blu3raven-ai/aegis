import { test, expect } from "@playwright/test"

// Override the project-level storageState — these tests exercise the auth
// boundary directly and need a clean browser context for the 401 scenario.
test.use({ storageState: { cookies: [], origins: [] } })

const E2E_USERNAME = process.env.E2E_USERNAME ?? "admin"
const E2E_PASSWORD = process.env.E2E_PASSWORD ?? ""

async function login(page: import("@playwright/test").Page) {
  await page.goto("/login")
  await page.locator('input[placeholder="you@example.com or username"]').fill(E2E_USERNAME)
  await page.locator('input[type="password"]').fill(E2E_PASSWORD)
  await page.locator('button[type="submit"]').click()
  // Global-setup confirms post-login lands on "/"
  await page.waitForURL("**/", { timeout: 10_000 })
}

test.describe("PR 2 — Pilot: compliance listFrameworks via apiClient", () => {
  test("logged-in user loads the compliance page and frameworks populate", async ({ page }) => {
    const pageErrors: string[] = []
    page.on("pageerror", (err) => pageErrors.push(err.message))

    await login(page)
    await page.goto("/compliance")

    // The FrameworkSelector <select> is populated by listFrameworks() via apiClient.
    // Wait for the element to be visible; once frameworks arrive, the <select>
    // renders with options and is no longer an empty control.
    await expect(page.getByTestId("framework-selector")).toBeVisible({ timeout: 10_000 })

    // Confirm at least one framework option exists (data actually loaded)
    const optionCount = await page.getByTestId("framework-selector").locator("option").count()
    expect(optionCount).toBeGreaterThan(0)

    // No uncaught JS errors during the load
    expect(pageErrors).toHaveLength(0)
  })

  test("apiClient redirects to /login when session expires (401 path)", async ({ page, context }) => {
    await login(page)

    // Wipe all cookies to simulate session expiry — next request to
    // /api/v1/compliance/frameworks will return 401, and apiClient calls
    // window.location.assign("/login") on any 401 response.
    await context.clearCookies()

    await page.goto("/compliance")

    // apiClient 401 handler triggers window.location.assign("/login")
    await page.waitForURL("**/login", { timeout: 10_000 })
    expect(page.url()).toContain("/login")
  })
})
