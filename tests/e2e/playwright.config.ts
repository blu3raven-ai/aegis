import { defineConfig } from "@playwright/test"
import path from "node:path"

// Absolute so global-setup (which writes it) and the projects (which read it)
// agree regardless of the directory Playwright is invoked from.
const STORAGE_STATE = path.join(__dirname, ".auth", "admin.json")

export default defineConfig({
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  testDir: "./tests",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  outputDir: "./test-results",
  projects: [
    {
      name: "critical",
      testDir: "./tests/critical",
      use: { storageState: STORAGE_STATE },
      fullyParallel: false,
      workers: 1,
    },
    {
      name: "ui",
      testDir: "./tests/ui",
      use: { storageState: STORAGE_STATE },
      fullyParallel: true,
    },
    {
      name: "settings",
      testDir: "./tests/settings",
      use: { storageState: STORAGE_STATE },
      fullyParallel: true,
    },
  ],
})
