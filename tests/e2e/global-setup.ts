import { chromium, type FullConfig } from "@playwright/test"
import fs from "node:fs"
import path from "node:path"

const AUTH_DIR = path.join(__dirname, ".auth")
const ADMIN_STATE = path.join(AUTH_DIR, "admin.json")
const SEED_MANIFEST = path.join(AUTH_DIR, "seed-manifest.json")

// The combined production image serves the API and the app on the same port, so
// both default to :3000. A split dev stack can override E2E_API_URL (:8000).
const APP = process.env.E2E_BASE_URL ?? "http://localhost:3000"
const API = process.env.E2E_API_URL ?? "http://localhost:3000"

async function globalSetup(config: FullConfig) {
  const projects = config.projects.map((p) => p.name)
  const needsBackend = projects.includes("critical")

  fs.mkdirSync(AUTH_DIR, { recursive: true })

  // Clean up stale seed data from previous run
  if (fs.existsSync(SEED_MANIFEST)) {
    try {
      await cleanupSeedData()
    } catch {
      // Best-effort cleanup
    }
  }

  if (!needsBackend) {
    // For mocked-only runs, create a dummy auth state
    // (mocked tests intercept all API calls anyway)
    fs.writeFileSync(ADMIN_STATE, JSON.stringify({ cookies: [], origins: [] }))
    return
  }

  // Health check — fail fast if the stack isn't running
  try {
    const res = await fetch(`${API}/health`)
    if (!res.ok) throw new Error(`Health check returned ${res.status}`)
  } catch (err) {
    throw new Error(
      `Health check at ${API}/health failed. Bring the stack up (docker compose up -d) before the critical e2e tests.\n` +
        String(err)
    )
  }

  // Login and save auth state
  const browser = await chromium.launch()
  const page = await browser.newPage()

  const username = process.env.E2E_USERNAME ?? "admin"
  const password = process.env.E2E_PASSWORD
  if (!password) {
    throw new Error("E2E_PASSWORD env var is required for critical e2e tests")
  }

  await page.goto(`${APP}/login`)
  await page.locator("#email").fill(username)
  await page.locator("#password").fill(password)
  await page.locator('button[type="submit"]').click()
  // Any authenticated landing page confirms the session cookie — just off /login.
  await page.waitForURL((url) => !url.pathname.startsWith("/login"), { timeout: 20_000 })

  await page.context().storageState({ path: ADMIN_STATE })
  await browser.close()

  // Seed test data
  await seedTestData()
}

async function seedTestData() {
  // The seed endpoint is public under its ENABLE_TEST_ENDPOINTS gate; send no
  // cookie so the CSRF check (which only fires on an authenticated request) is
  // skipped, matching the cookie-less teardown.
  const res = await fetch(`${API}/api/v1/test/seed`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "seed" }),
  })

  if (!res.ok) {
    const text = await res.text()
    throw new Error(`Seed endpoint failed (${res.status}): ${text}`)
  }

  const manifest = await res.json()
  fs.writeFileSync(SEED_MANIFEST, JSON.stringify(manifest, null, 2))
}

async function cleanupSeedData() {
  const manifest = JSON.parse(fs.readFileSync(SEED_MANIFEST, "utf-8"))
  if (!manifest?.seeded) return

  try {
    await fetch(`${API}/api/v1/test/seed`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "teardown", manifest }),
    })
  } finally {
    fs.unlinkSync(SEED_MANIFEST)
  }
}

export default globalSetup
