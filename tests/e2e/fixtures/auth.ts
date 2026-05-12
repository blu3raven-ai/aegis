import { test as base } from "@playwright/test"

/**
 * Default test fixture — uses admin auth state from global-setup.
 * storageState is configured at the project level in playwright.config.ts.
 */
export const test = base
export { expect } from "@playwright/test"
