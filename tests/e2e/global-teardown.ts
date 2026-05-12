import fs from "node:fs"
import path from "node:path"

const AUTH_DIR = path.join(__dirname, ".auth")
const SEED_MANIFEST = path.join(AUTH_DIR, "seed-manifest.json")

async function globalTeardown() {
  // Clean up seeded data
  if (fs.existsSync(SEED_MANIFEST)) {
    try {
      const manifest = JSON.parse(fs.readFileSync(SEED_MANIFEST, "utf-8"))
      if (manifest?.seeded) {
        await fetch("http://localhost:8000/test/seed", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: "teardown", manifest }),
        })
      }
    } catch {
      // Best-effort cleanup
    }
  }

  // Remove auth directory
  if (fs.existsSync(AUTH_DIR)) {
    fs.rmSync(AUTH_DIR, { recursive: true })
  }
}

export default globalTeardown
