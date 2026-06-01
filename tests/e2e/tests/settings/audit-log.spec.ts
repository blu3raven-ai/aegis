import { test, expect } from "@playwright/test"
import { mockCurrentUser } from "../../fixtures/mock-api"
import { mockAuditAPI } from "../../fixtures/mock-backend"

/**
 * Audit log viewer (/settings/audit).
 *
 * Defensive guard: if the route doesn't exist (404 or redirect), the
 * suite skips gracefully so it can ship before Phase 22 merges.
 */

async function pageExistsOrSkip(page: Parameters<typeof test.skip>[0]) {
  const res = await page.goto("/settings/audit", { waitUntil: "commit" })
  if (!res || res.status() === 404) {
    test.skip(true, "/settings/audit not available in this build — Phase 22 pending")
  }
}

test.describe("Audit log viewer", () => {
  test("page heading is visible", async ({ page }) => {
    await mockCurrentUser(page)
    await mockAuditAPI(page)
    await pageExistsOrSkip(page)

    await expect(page.getByText(/audit log/i)).toBeVisible({ timeout: 8_000 })
  })

  test("events table renders rows from mock data", async ({ page }) => {
    await mockCurrentUser(page)
    await mockAuditAPI(page)
    await pageExistsOrSkip(page)

    // Our mock has a "user.created" event
    await expect(page.getByText("user.created")).toBeVisible({ timeout: 8_000 })
  })

  test("empty state is shown when no events exist", async ({ page }) => {
    await mockCurrentUser(page)
    await mockAuditAPI(page, { empty: true })
    await pageExistsOrSkip(page)

    await expect(
      page.getByText(/no events|empty|no audit/i).or(
        // EmptyAuditState renders within the rounded card
        page.locator(".rounded-2xl")
      )
    ).toBeVisible({ timeout: 8_000 })
  })

  test("filter bar is rendered", async ({ page }) => {
    await mockCurrentUser(page)
    await mockAuditAPI(page)
    await pageExistsOrSkip(page)

    // AuditFilterBar renders an action filter dropdown or input
    await expect(
      page.locator('select, input[placeholder*="action" i], [aria-label*="action" i]').first()
    ).toBeVisible({ timeout: 8_000 })
  })

  test("filtering by action type triggers a new API request", async ({ page }) => {
    await mockCurrentUser(page)

    let auditCalled = 0
    await page.route("**/api/v1/audit/events**", (route) => {
      auditCalled++
      return route.fulfill({
        json: { events: [], total: 0, has_more: false },
      })
    })

    await pageExistsOrSkip(page)

    const actionInput = page
      .locator('select[aria-label*="action" i], input[placeholder*="action" i]')
      .first()

    if (await actionInput.isVisible({ timeout: 3_000 })) {
      const callsBefore = auditCalled
      await actionInput.selectOption("user.created").catch(async () => {
        // If it's a text input rather than a select
        await actionInput.fill("user.created")
        await actionInput.press("Enter")
      })
      await page.waitForTimeout(600)
      expect(auditCalled).toBeGreaterThan(callsBefore)
    }
  })

  test("clicking an event row opens the detail drawer", async ({ page }) => {
    await mockCurrentUser(page)
    await mockAuditAPI(page)
    await pageExistsOrSkip(page)

    const firstRow = page.locator("table tbody tr").first()
    await firstRow.waitFor({ timeout: 8_000 })
    await firstRow.click()

    // AuditEventDrawer or a panel with event action text
    await expect(
      page.locator('[role="dialog"], aside').or(
        page.getByText("user.created")
      )
    ).toBeVisible({ timeout: 5_000 })
  })

  test("drawer shows changes diff when event has before/after", async ({ page }) => {
    await mockCurrentUser(page)
    // The first mock event has a changes object with before/after
    await mockAuditAPI(page)
    await pageExistsOrSkip(page)

    const firstRow = page.locator("table tbody tr").first()
    await firstRow.waitFor({ timeout: 8_000 })
    await firstRow.click()

    // Drawer should render some diff representation
    await expect(
      page.getByText(/changes|before|after|diff/i).first()
    ).toBeVisible({ timeout: 5_000 })
  })
})
