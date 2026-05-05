"use client"

import type { CodeScanningScanRun } from "@/lib/client/code-scanning-client"
import type { GqlCodeScanningAnalytics } from "@/lib/shared/graphql/types"
import { ScanHealthTable, type ScanHealthRun } from "@/components/shared/ScanHealthTable"
import { RepositoryCoverageTable, type RepoCoverageRow } from "@/components/shared/RepositoryCoverageTable"
import { CoverageGapsCard } from "@/components/shared/CoverageGapsCard"

export function CodeScanningHealthTab({
  latestRun,
  lastCompleted,
  analytics,
  coverageGaps = [],
}: {
  latestRun: CodeScanningScanRun | null
  lastCompleted: CodeScanningScanRun | null
  analytics: GqlCodeScanningAnalytics | null
  coverageGaps?: Array<{ repository: string; reason: string; lastScannedAt: string | null }>
}) {
  const topRepos = analytics?.topRepositories ?? []

  const runs: ScanHealthRun[] = []
  if (latestRun) {
    runs.push({
      id: latestRun.id,
      status: latestRun.status,
      createdAt: latestRun.createdAt,
      startedAt: latestRun.startedAt,
      finishedAt: latestRun.finishedAt,
      durationSeconds: latestRun.durationSeconds,
      findingsCount: latestRun.findingsCount,
      error: latestRun.error,
      progress: latestRun.progress,
    })
  }
  if (lastCompleted && lastCompleted.id !== latestRun?.id) {
    runs.push({
      id: lastCompleted.id,
      status: lastCompleted.status,
      createdAt: lastCompleted.createdAt,
      startedAt: lastCompleted.startedAt,
      finishedAt: lastCompleted.finishedAt,
      durationSeconds: lastCompleted.durationSeconds,
      findingsCount: lastCompleted.findingsCount,
      error: lastCompleted.error,
      progress: lastCompleted.progress,
    })
  }

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
