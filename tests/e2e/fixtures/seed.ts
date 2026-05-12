/**
 * Seed test data into the backend for Tier 1 (critical) tests.
 * Uses the test seed endpoint (POST /test/seed).
 */

interface SeedManifest {
  seeded: boolean
  org: string
  count: number
  fingerprints: string[]
}

export async function seedTestData(cookieHeader: string): Promise<SeedManifest> {
  const res = await fetch("http://localhost:8000/test/seed", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: cookieHeader,
    },
    body: JSON.stringify({ action: "seed" }),
  })

  if (!res.ok) {
    const text = await res.text()
    throw new Error(`Seed failed (${res.status}): ${text}`)
  }

  return res.json() as Promise<SeedManifest>
}

export async function teardownTestData(manifest: SeedManifest): Promise<void> {
  const res = await fetch("http://localhost:8000/test/seed", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "teardown", manifest }),
  })

  if (!res.ok) {
    console.warn(`Teardown failed (${res.status}): ${await res.text()}`)
  }
}
