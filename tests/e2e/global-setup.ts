import { chromium, type FullConfig } from "@playwright/test"
import fs from "node:fs"
import path from "node:path"

const AUTH_DIR = path.join(__dirname, ".auth")
const ADMIN_STATE = path.join(AUTH_DIR, "admin.json")
const SEED_MANIFEST = path.join(AUTH_DIR, "seed-manifest.json")

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

  // Health check — fail fast if backend isn't running
  try {
    const res = await fetch("http://localhost:8000/health")
    if (!res.ok) throw new Error(`Health check returned ${res.status}`)
  } catch (err) {
    throw new Error(
      "Backend health check failed. Run `docker-compose up -d` before running critical e2e tests.\n" +
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

  await page.goto("http://localhost:3000/login")
  await page.locator('input[placeholder="you@example.com or username"]').fill(username)
  await page.locator('input[type="password"]').fill(password)
  await page.locator('button[type="submit"]').click()
  await page.waitForURL("http://localhost:3000/", { timeout: 10_000 })

  await page.context().storageState({ path: ADMIN_STATE })
  await browser.close()

  // Seed test data
  await seedTestData()
}

async function seedTestData() {
  const adminState = JSON.parse(fs.readFileSync(ADMIN_STATE, "utf-8"))
  const cookies = adminState.cookies ?? []
  const cookieHeader = cookies.map((c: { name: string; value: string }) => `${c.name}=${c.value}`).join("; ")

  const res = await fetch("http://localhost:8000/api/v1/test/seed", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: cookieHeader,
    },
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
    await fetch("http://localhost:8000/api/v1/test/seed", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "teardown", manifest }),
    })
  } finally {
    fs.unlinkSync(SEED_MANIFEST)
  }
}

export default globalSetup
