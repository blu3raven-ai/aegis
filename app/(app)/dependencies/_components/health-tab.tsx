import type { DependenciesHealthRunEntry } from "@/lib/shared/dependencies/types"
import { ScanHealthTable, type ScanHealthRun } from "@/components/shared/ScanHealthTable"
import { CoverageGapsCard } from "@/components/shared/CoverageGapsCard"

export function DependenciesHealthTab({
  runHistory = [],
  coverageGaps = [],
  lastCompletedAt,
  org,
  canRefresh,
}: {
  runHistory?: DependenciesHealthRunEntry[]
  coverageGaps?: Array<{ repository: string; reason: string; lastScannedAt: string | null }>
  lastCompletedAt?: string | null
  org: string
  canRefresh?: boolean
}) {
  const runs: ScanHealthRun[] = runHistory.map((r) => ({
    id: r.id ?? "",
    status: r.status ?? "unknown",
    mode: r.scanMode ?? null,
    createdAt: r.createdAt,
    startedAt: r.startedAt ?? r.createdAt,
    finishedAt: r.finishedAt,
    durationSeconds: r.durationSeconds,
    findingsCount: r.findingsCount,
    error: r.error,
    progress: r.progress,
  }))

  return (
    <div className="space-y-6">
      <ScanHealthTable runs={runs} toolLabel="Dependencies" />
      <CoverageGapsCard gaps={coverageGaps} />
    </div>
  )
}
