import { defineConfig } from "@playwright/test"
import path from "node:path"

// Absolute so it resolves identically no matter which directory Playwright is
// invoked from (smoke-setup writes to the same path).
const STORAGE_STATE = path.join(__dirname, ".auth", "smoke.json")

/**
 * Whole-app smoke run against the real, built stack (docker compose up --build).
 * Logs in once (smoke-setup) then loads every core page and asserts it renders
 * without a crash, an error banner, or an uncaught exception. This is the
 * "did this push break prod" gate — it exercises the production image end to
 * end, not mocked responses.
 */
export default defineConfig({
  testDir: "./tests/smoke",
  outputDir: "./test-results-smoke",
  globalSetup: "./smoke-setup.ts",
  timeout: 45_000,
  expect: { timeout: 15_000 },
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [["list"], ["html", { outputFolder: "playwright-report-smoke", open: "never" }]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    storageState: STORAGE_STATE,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
})
