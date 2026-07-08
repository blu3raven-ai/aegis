import { chromium, type FullConfig } from "@playwright/test"
import fs from "node:fs"
import path from "node:path"

/**
 * Smoke global-setup: verify the backend is up and log in once as the admin,
 * saving the authenticated storage state. Unlike the critical suite this does
 * NOT seed test data — the smoke run only checks that the real, built app boots
 * and renders its core pages, so the seeded admin from db/seed is enough.
 */
const AUTH_DIR = path.join(__dirname, ".auth")
const SMOKE_STATE = path.join(AUTH_DIR, "smoke.json")

const BASE = process.env.E2E_BASE_URL ?? "http://localhost:3000"
// The backend health endpoint is served on the app port in the combined image.
const HEALTH = `${BASE}/health`

async function globalSetup(_config: FullConfig) {
  fs.mkdirSync(AUTH_DIR, { recursive: true })

  // Fail fast (with a clear message) if the stack isn't up yet.
  let healthy = false
  for (let i = 0; i < 60 && !healthy; i++) {
    try {
      const res = await fetch(HEALTH)
      healthy = res.ok
    } catch {
      /* not up yet */
    }
    if (!healthy) await new Promise((r) => setTimeout(r, 2000))
  }
  if (!healthy) {
    throw new Error(`App health check at ${HEALTH} never passed — is the stack running?`)
  }

  const username = process.env.E2E_USERNAME ?? "admin"
  const password = process.env.E2E_PASSWORD
  if (!password) {
    throw new Error("E2E_PASSWORD env var is required for the smoke run")
  }

  const browser = await chromium.launch()
  const page = await browser.newPage()
  await page.goto(`${BASE}/login`)
  await page.locator("#email").fill(username)
  await page.locator("#password").fill(password)

  // Submit, retrying on a login rate-limit (429) — a busy shared runner can trip
  // it. Each attempt waits on the /auth/login response so we can read the status.
  for (let attempt = 0; attempt < 5; attempt++) {
    const [resp] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/api/v1/auth/login"), { timeout: 15_000 }),
      page.locator('button[type="submit"]').click(),
    ])
    if (resp.status() !== 429) break
    await page.waitForTimeout(5000 * (attempt + 1))
  }

  // Any authenticated landing page (root, onboarding, findings, …) confirms the
  // session cookie is set — just not still on /login.
  await page.waitForURL((url) => !url.pathname.startsWith("/login"), { timeout: 20_000 })
  await page.context().storageState({ path: SMOKE_STATE })
  await browser.close()
}

export default globalSetup
