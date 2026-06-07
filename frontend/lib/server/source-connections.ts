const BACKEND_URL = process.env.FASTAPI_URL ?? "http://localhost:8000"

interface SourceConnectionEntry {
  auth?: { orgOrOwner?: string }
  sourceType?: string
  category?: string
  status?: string
}

let _cachedConnections: SourceConnectionEntry[] | null = null
let _cacheTime = 0
const CACHE_TTL = 10_000 // 10 seconds

async function fetchSourceConnections(): Promise<SourceConnectionEntry[]> {
  const now = Date.now()
  if (_cachedConnections && now - _cacheTime < CACHE_TTL) {
    return _cachedConnections
  }
  try {
    const response = await fetch(`${BACKEND_URL}/settings/api/sources/internal-orgs`, {
      cache: "no-store",
    })
    if (!response.ok) return _cachedConnections ?? []
    const data = await response.json()
    const connections: SourceConnectionEntry[] = Array.isArray(data.connections) ? data.connections : []
    _cachedConnections = connections
    _cacheTime = now
    return connections
  } catch {
    return _cachedConnections ?? []
  }
}

/** Backend normalizes "container-registry" → "container-images"; map it back for matching. */
function normalizeCategory(category: string): string {
  return category === "container-images" ? "container-registry" : category
}

export async function getOrgsForCategories(categories: string[]): Promise<string[]> {
  const categorySet = new Set(categories)
  const byKey = new Map<string, string>()
  for (const conn of await fetchSourceConnections()) {
    if (conn.status !== "connected") continue
    if (!conn.category || !categorySet.has(normalizeCategory(conn.category))) continue
    const org = conn.auth?.orgOrOwner?.trim()
    if (!org) continue
    const key = org.toLowerCase()
    if (!byKey.has(key)) byKey.set(key, org)
  }
  return Array.from(byKey.values())
}

