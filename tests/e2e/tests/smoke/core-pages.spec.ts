import { test, expect } from "@playwright/test"

/**
 * Whole-app smoke: every core page must render against the real built stack —
 * no redirect back to login, the app shell present, no "failed to load" banner,
 * and no uncaught exception during navigation. Catches a push that breaks the
 * production image (bad build, broken query, crashing component) before deploy.
 */
// The canonical top-level routes, taken from the sidebar navigation.
const ROUTES: { path: string; name: string }[] = [
  { path: "/", name: "Home dashboard" },
  { path: "/findings", name: "Findings" },
  { path: "/sources", name: "Sources" },
  { path: "/sbom", name: "SBOM" },
  { path: "/policies", name: "Policies" },
  { path: "/compliance", name: "Compliance" },
  { path: "/reports", name: "Reports" },
  { path: "/insights", name: "Insights" },
  { path: "/chains", name: "Attack chains" },
  { path: "/integrations", name: "Integrations" },
  { path: "/notifications", name: "Notifications" },
  { path: "/inbox", name: "Inbox" },
  { path: "/members", name: "Members" },
  { path: "/roles", name: "Roles" },
  { path: "/teams", name: "Teams" },
  { path: "/settings", name: "Settings" },
]

for (const route of ROUTES) {
  test(`renders ${route.name} (${route.path})`, async ({ page }) => {
    const errors: string[] = []
    page.on("pageerror", (e) => errors.push(String(e)))

    // domcontentloaded, not networkidle: several pages hold an SSE/polling
    // connection open, so the network never goes idle. The explicit element
    // wait below is the real "page rendered" signal.
    await page.goto(route.path, { waitUntil: "domcontentloaded" })

    // The app shell rendered (didn't white-screen) — the sidebar navigation
    // is present on every authenticated page.
    await expect(page.getByRole("navigation").first()).toBeVisible()

    // Session valid and the route resolved — not bounced to the login screen.
    await expect(page).not.toHaveURL(/\/login(\?|$)/)

    // No hard "data failed to load" banner.
    await expect(page.getByText("Some data failed to load")).toHaveCount(0)

    // No uncaught exceptions during load.
    expect(errors, `uncaught errors on ${route.path}:\n${errors.join("\n")}`).toEqual([])
  })
}
