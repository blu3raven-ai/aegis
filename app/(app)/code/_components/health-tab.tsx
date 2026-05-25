"use client"

import type { CodeScanningScanRun } from "@/lib/client/code-scanning-client"
import type { GqlCodeScanningAnalytics } from "@/lib/shared/graphql/types"
import { ScanHealthTable, type ScanHealthRun } from "@/components/shared/ScanHealthTable"
import { RepositoryCoverageTable, type RepoCoverageRow } from "@/components/shared/RepositoryCoverageTable"
import { CoverageGapsCard } from "@/components/shared/CoverageGapsCard"

export function CodeScanningHealthTab({
  runHistory = [],
  analytics,
  coverageGaps = [],
}: {
  runHistory?: CodeScanningScanRun[]
  analytics: GqlCodeScanningAnalytics | null
  coverageGaps?: Array<{ repository: string; reason: string; lastScannedAt: string | null }>
}) {
  const topRepos = analytics?.topRepositories ?? []

  const runs: ScanHealthRun[] = runHistory.map((r) => ({
    id: r.id,
    status: r.status,
    mode: r.scanMode ?? null,
    createdAt: r.createdAt,
    startedAt: r.startedAt,
    finishedAt: r.finishedAt,
    durationSeconds: r.durationSeconds,
    findingsCount: r.findingsCount,
    error: r.error,
    progress: r.progress,
  }))

  return (
    <div className="space-y-6">
      <ScanHealthTable runs={runs} toolLabel="Code" />
      <CoverageGapsCard gaps={coverageGaps} />
      <RepositoryCoverageTable
        repos={topRepos.map((repo): RepoCoverageRow => ({
          name: repo.name.split("/").pop() ?? repo.name,
          fullName: repo.name,
          alertCount: repo.open,
          lastUpdatedAt: null,
        }))}
      />
    </div>
  )
}
