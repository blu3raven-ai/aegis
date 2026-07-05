import { test, expect } from "@playwright/test"
import { mockCurrentUser } from "../../fixtures/mock-api"

test.describe("Source connections settings", () => {
  test.beforeEach(async ({ page }) => {
    await mockCurrentUser(page)
    // listSourceConnections is now a GraphQL query against /api/v1/graphql.
    // Intercept any POST landing there and return a minimal payload for the
    // sourceConnections operation.
    await page.route("**/api/v1/graphql", async (route) => {
      const body = JSON.parse(route.request().postData() || "{}")
      if (body.operationName === "SourceConnections") {
        await route.fulfill({
          json: {
            data: {
              sourceConnections: {
                connections: [
                  {
                    id: "conn-1",
                    sourceType: "github",
                    category: "code-repositories",
                    name: "acme-corp",
                    status: "connected",
                    auth: { orgOrOwner: "acme-corp", username: null, instanceUrl: null, groupOrProject: null },
                    scanScope: "all",
                    excludedItems: [],
                    syncSchedule: "6h",
                    statusMessage: null,
                    lastSyncedAt: null,
                    nextSyncAt: null,
                    discoveredItemCount: null,
                    discoveredItems: [],
                    createdAt: "2026-06-01T00:00:00Z",
                    updatedAt: "2026-06-01T00:00:00Z",
                  },
                ],
              },
            },
          },
        })
        return
      }
      await route.continue()
    })
  })

  test("source connections page loads", async ({ page }) => {
    await page.goto("/settings/sources")
    await expect(page.getByText(/source/i)).toBeVisible({ timeout: 5000 })
  })
})
