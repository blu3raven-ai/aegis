import type { DependenciesFinding } from "@/lib/shared/dependencies/types"
import { RepositoryCoverageTable, type RepoCoverageRow } from "@/components/shared/RepositoryCoverageTable"

function buildRepoCoverage(findings: DependenciesFinding[]): RepoCoverageRow[] {
  const map = new Map<string, RepoCoverageRow>()
  for (const f of findings) {
    const key = f.repository.full_name
    const existing = map.get(key)
    if (!existing) {
      map.set(key, {
        name: f.repository.name,
        fullName: f.repository.full_name,
        alertCount: 1,
        lastUpdatedAt: f.updated_at,
      })
    } else {
      existing.alertCount += 1
      if (f.updated_at && (!existing.lastUpdatedAt || new Date(f.updated_at) > new Date(existing.lastUpdatedAt))) {
        existing.lastUpdatedAt = f.updated_at
      }
    }
  }
  return Array.from(map.values()).sort((a, b) => b.alertCount - a.alertCount)
}

export function HealthCoverage({
  allFindings,
}: {
  allFindings: DependenciesFinding[]
  lastRefreshedAt?: string | null
  org?: string
  canRefresh?: boolean
}) {
  return <RepositoryCoverageTable repos={buildRepoCoverage(allFindings)} />
}
