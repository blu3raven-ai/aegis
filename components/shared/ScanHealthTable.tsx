import { InsightCard } from "@/components/shared/InsightCard"
import { formatScanTimestamp } from "@/lib/shared/utils"

export interface ScanHealthRun {
  id: string
  status: string
  mode?: string | null
  createdAt?: string | null
  startedAt?: string | null
  finishedAt?: string | null
  durationSeconds?: number | null
  findingsCount?: number | null
  error?: string | null
  progress?: {
    expectedRepos?: number | null
    finishedRepos?: number | null
  } | null
}

const MODE_STYLES: Record<string, string> = {
  light: "bg-blue-500/10 text-blue-400",
  deep: "bg-purple-500/10 text-purple-400",
  ai_enhanced: "bg-emerald-500/10 text-emerald-400",
  full: "bg-blue-500/10 text-blue-400",
  sbom_only: "bg-amber-500/10 text-amber-400",
  advisories_only: "bg-purple-500/10 text-purple-400",
}

const MODE_LABELS: Record<string, string> = {
  light: "Light",
  deep: "Deep",
  ai_enhanced: "AI Enhanced",
  full: "Full",
  sbom_only: "SBOMs only",
  advisories_only: "Advisories only",
}


function durationLabel(seconds: number | null | undefined) {
  if (typeof seconds !== "number") return "—"
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return m > 0 ? `${m}m ${s}s` : `${s}s`
}

function statusColour(status: string) {
  if (status === "completed") return "text-emerald-400"
  if (status === "failed") return "text-red-400"
  if (status === "cancelled") return "text-[var(--color-text-secondary)]"
  return "text-amber-400"
}

function ModeBadge({ mode }: { mode?: string | null }) {
  if (!mode) return <span className="text-[var(--color-text-secondary)]">—</span>
  const label = MODE_LABELS[mode] ?? mode.replaceAll("_", " ")
  const style = MODE_STYLES[mode] ?? "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
  return <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${style}`}>{label}</span>
}

function RunRow({ label, run, showMode }: { label: string; run: ScanHealthRun; showMode: boolean }) {
  const repos = run.progress
    ? `${run.progress.finishedRepos ?? 0} / ${run.progress.expectedRepos ?? "?"}`
    : "—"

  return (
    <tr className={run.status === "failed" ? "bg-red-500/5" : "transition-colors hover:bg-[var(--color-surface-raised)]"}>
      <td className="px-4 py-3 text-xs font-semibold uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">{label}</td>
      <td className="px-4 py-3 text-[var(--color-text-primary)]">{formatScanTimestamp(run.startedAt ?? run.createdAt)}</td>
      <td className="px-4 py-3">
        <span className={`capitalize ${statusColour(run.status)}`}>
          {run.status.replaceAll("_", " ")}
        </span>
      </td>
      {showMode && (
        <td className="px-4 py-3"><ModeBadge mode={run.mode} /></td>
      )}
      <td className="px-4 py-3 text-[var(--color-text-secondary)]">{durationLabel(run.durationSeconds)}</td>
      <td className="px-4 py-3 text-[var(--color-text-secondary)]">{repos}</td>
      <td className="px-4 py-3 text-right font-semibold text-[var(--color-text-primary)]">
        {run.findingsCount ?? "—"}
      </td>
      {run.error ? (
        <td className="max-w-xs px-4 py-3 text-xs text-red-400 break-words">{run.error}</td>
      ) : (
        <td className="px-4 py-3" />
      )}
    </tr>
  )
}

export function ScanHealthTable({
  runs,
  toolLabel = "scanner",
}: {
  runs: ScanHealthRun[]
  toolLabel?: string
}) {
  const showMode = runs.some((r) => r.mode)
  const colCount = showMode ? 8 : 7

  return (
    <InsightCard
      eyebrow="Scan Health"
      title="Recent scanner runs"
      description={`Status and outcomes of the most recent ${toolLabel} scans.`}
    >
      <div className="overflow-auto rounded-2xl border border-[var(--color-border)]">
        <table className="min-w-full divide-y divide-[var(--color-border)] text-sm">
          <thead className="bg-[var(--color-surface-raised)] text-left text-xs uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
            <tr>
              <th className="px-4 py-3">Run</th>
              <th className="px-4 py-3">Started</th>
              <th className="px-4 py-3">Status</th>
              {showMode && <th className="px-4 py-3">Mode</th>}
              <th className="px-4 py-3">Duration</th>
              <th className="px-4 py-3">Repos</th>
              <th className="px-4 py-3 text-right">Findings</th>
              <th className="px-4 py-3">Error</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)]">
            {runs.length > 0 ? (
              runs.map((run, i) => (
                <RunRow
                  key={run.id ?? `run-${i}`}
                  label={i === 0 ? "Latest" : `Run ${runs.length - i}`}
                  run={run}
                  showMode={showMode}
                />
              ))
            ) : (
              <tr>
                <td colSpan={colCount} className="px-4 py-6 text-center text-sm text-[var(--color-text-secondary)]">
                  No scan runs yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </InsightCard>
  )
}
