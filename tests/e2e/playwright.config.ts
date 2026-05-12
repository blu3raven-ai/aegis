import { defineConfig } from "@playwright/test"

export default defineConfig({
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  testDir: "./tests",
  use: {
    baseURL: "http://localhost:3000",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  outputDir: "./test-results",
  projects: [
    {
      name: "critical",
      testDir: "./tests/critical",
      use: { storageState: ".auth/admin.json" },
      fullyParallel: false,
      workers: 1,
    },
    {
      name: "ui",
      testDir: "./tests/ui",
      use: { storageState: ".auth/admin.json" },
      fullyParallel: true,
    },
    {
      name: "settings",
      testDir: "./tests/settings",
      use: { storageState: ".auth/admin.json" },
      fullyParallel: true,
    },
  ],
})
