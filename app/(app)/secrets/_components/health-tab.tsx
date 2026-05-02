import { InsightCard } from "@/components/shared/InsightCard"
import { ScanHealthTable, type ScanHealthRun } from "@/components/shared/ScanHealthTable"
import { RepositoryCoverageTable, type RepoCoverageRow } from "@/components/shared/RepositoryCoverageTable"
import { CoverageGapsCard } from "@/components/shared/CoverageGapsCard"
import type { SecretFinding } from "@/lib/shared/secrets/types"
import type { SecretsCoverageGap, SecretsHealthRunEntry } from "@/lib/shared/secrets/types"



const DEPTH_META: Record<string, { label: string; className: string }> = {
  light: { label: "Light", className: "bg-blue-500/10 text-blue-400" },
  deep: { label: "Deep", className: "bg-purple-500/10 text-purple-400" },
  ai_enhanced: { label: "AI Enhanced", className: "bg-emerald-500/10 text-emerald-400" },
}

function depthMeta(depth: string | undefined) {
  return DEPTH_META[depth ?? ""] ?? DEPTH_META.light
}

function buildDepthStats(runHistory: SecretsHealthRunEntry[]) {
  const depths = ["light", "deep", "ai_enhanced"] as const
  return depths.map((depth) => {
    const runs = runHistory.filter((r) => (r.scanDepth ?? "light") === depth)
    const completed = runs.filter((r) => r.status === "completed")
    const totalFindings = completed.reduce((s, r) => s + (r.findingsCount ?? 0), 0)
    const totalDistinctFindings = completed.reduce((s, r) => s + (r.distinctFindingsCount ?? 0), 0)
    const hitRate = runs.length > 0 ? Math.round((completed.filter((r) => (r.findingsCount ?? 0) > 0).length / runs.length) * 100) : null
    const avg = completed.length > 0 ? (totalFindings / completed.length).toFixed(1) : null
    return { depth, runs: runs.length, completed: completed.length, totalFindings, totalDistinctFindings, hitRate, avg }
  }).filter((s) => s.runs > 0)
}

function buildRepoCoverage(findings: SecretFinding[]): RepoCoverageRow[] {
  const map = new Map<string, RepoCoverageRow>()
  for (const f of findings) {
    const key = `${f.organization}/${f.repository}`
    const existing = map.get(key)
    if (!existing) {
      map.set(key, {
        name: f.repository,
        fullName: key,
        alertCount: 1,
        lastUpdatedAt: f.detectedAt,
      })
    } else {
      existing.alertCount += 1
      if (f.detectedAt && (!existing.lastUpdatedAt || f.detectedAt > existing.lastUpdatedAt)) {
        existing.lastUpdatedAt = f.detectedAt
      }
    }
  }
  return Array.from(map.values()).sort((a, b) => b.alertCount - a.alertCount)
}

export function HealthTab({
  runHistory,
  coverageGaps,
  findings = [],
}: {
  runHistory: SecretsHealthRunEntry[]
  coverageGaps: SecretsCoverageGap[]
  findings?: SecretFinding[]
}) {
  const depthStats = buildDepthStats(runHistory)

  const runs: ScanHealthRun[] = runHistory.map((r) => ({
    id: r.id,
    status: r.status,
    mode: r.scanDepth ?? null,
    createdAt: r.createdAt,
    startedAt: r.startedAt,
    finishedAt: r.finishedAt,
    durationSeconds: r.durationSeconds,
    findingsCount: r.findingsCount,
    error: r.error,
    progress: r.progress ? { expectedRepos: r.progress.expectedRepos, finishedRepos: r.progress.finishedRepos } : null,
  }))

  return (
    <div className="space-y-5">

      <ScanHealthTable runs={runs} toolLabel="secret" />

      {/* ── Scan Depth Breakdown ────────────────────────────────────────────── */}
      <InsightCard
        eyebrow="Scanner Effectiveness"
        title="Scan depth breakdown"
        description="Findings and hit rate by scan mode across all completed runs."
      >
        <div className="overflow-auto rounded-2xl border border-[var(--color-border)]">
          <table className="min-w-full divide-y divide-[var(--color-border)] text-sm">
            <thead className="bg-[var(--color-surface-raised)] text-left text-xs uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
              <tr>
                <th className="px-5 py-3">Scan mode</th>
                <th className="px-5 py-3 text-right">Total runs</th>
                <th className="px-5 py-3 text-right">Completed</th>
                <th className="px-5 py-3 text-right">Total findings</th>
                <th className="px-5 py-3 text-right">Hit rate</th>
                <th className="px-5 py-3 text-right">Avg findings / run</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--color-border)]">
              {depthStats.map((s) => {
                const meta = depthMeta(s.depth)
                return (
                  <tr key={s.depth} className="transition-colors hover:bg-[var(--color-surface-raised)]">
                    <td className="px-5 py-4">
                      <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${meta.className}`}>{meta.label}</span>
                    </td>
                    <td className="px-5 py-4 text-right text-[var(--color-text-secondary)]">{s.runs}</td>
                    <td className="px-5 py-4 text-right text-[var(--color-text-secondary)]">{s.completed}</td>
                    <td className="px-5 py-4 text-right font-semibold text-[var(--color-text-primary)]">
                      {s.totalFindings}
                      {s.totalDistinctFindings > 0 && (
                        <span className="ml-1.5 text-xs font-normal text-[var(--color-text-secondary)]">
                          ({s.totalDistinctFindings} distinct)
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-4 text-right">
                      {s.hitRate === null ? (
                        <span className="text-xs text-[var(--color-text-secondary)]">—</span>
                      ) : (
                        <span className={`font-semibold ${s.hitRate >= 70 ? "text-emerald-400" : s.hitRate >= 30 ? "text-amber-400" : "text-red-400"}`}>
                          {s.hitRate}%
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-4 text-right text-[var(--color-text-secondary)]">{s.avg ?? "—"}</td>
                  </tr>
                )
              })}
              {depthStats.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-6 text-center text-sm text-[var(--color-text-secondary)]">
                    No scan data yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </InsightCard>

      <CoverageGapsCard gaps={coverageGaps} />

      <RepositoryCoverageTable repos={buildRepoCoverage(findings)} />

    </div>
  )
}
