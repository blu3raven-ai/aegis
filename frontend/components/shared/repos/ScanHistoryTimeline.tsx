/**
 * Last N scan runs visualization — uses the same visual language as ScanHealthTable
 * but lighter, focused on a single repo's history across scanner types.
 */
import type { ScanRunRow } from "@/lib/client/repos-api"

const STATUS_STYLES: Record<string, string> = {
  completed: "text-[var(--color-status-ok)]",
  failed:    "text-[var(--color-severity-critical)]",
  cancelled: "text-[var(--color-text-secondary)]",
  running:   "text-[var(--color-state-pending)]",
  queued:    "text-[var(--color-state-pending)]",
}

const TOOL_LABELS: Record<string, string> = {
  dependencies:        "SCA",
  code_scanning:       "SAST",
  container_scanning:  "CONT",
  secrets:             "SEC",
}

function durationLabel(ms: number | null | undefined): string {
  if (ms == null) return "—"
  const s = Math.round(ms / 1000)
  const m = Math.floor(s / 60)
  return m > 0 ? `${m}m ${s % 60}s` : `${s}s`
}

function relativeTime(iso: string): string {
  if (!iso) return "—"
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 2) return "just now"
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

interface ScanHistoryTimelineProps {
  runs: ScanRunRow[]
}

export function ScanHistoryTimeline({ runs }: ScanHistoryTimelineProps) {
  if (runs.length === 0) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] overflow-hidden">
        <div className="bg-[var(--color-surface-raised)] px-5 py-3 flex gap-8">
          {[80, 72, 80, 72, 64].map((w, i) => (
            <div key={i} style={{ width: w }} className="h-3 rounded bg-[var(--color-border)] animate-pulse" />
          ))}
        </div>
        {[0, 1, 2].map(i => (
          <div key={i} className="flex items-center gap-8 px-5 py-3.5 border-t border-[var(--color-border)]">
            <div className="h-4 w-20 rounded bg-[var(--color-surface-raised)] animate-pulse" />
            <div className="h-5 w-18 rounded-full bg-[var(--color-surface-raised)] animate-pulse" />
            <div className="h-4 w-20 rounded bg-[var(--color-surface-raised)] animate-pulse" />
            <div className="h-4 w-16 rounded bg-[var(--color-surface-raised)] animate-pulse" />
            <div className="h-4 w-12 rounded bg-[var(--color-surface-raised)] animate-pulse ml-auto" />
          </div>
        ))}
        <p className="px-5 py-3 text-center text-xs text-[var(--color-text-tertiary)] border-t border-[var(--color-border)]">
          No scan history yet — trigger a scan above to get started.
        </p>
      </div>
    )
  }

  return (
    <div className="overflow-auto rounded-2xl border border-[var(--color-border)]">
      <table className="min-w-full divide-y divide-[var(--color-border)] text-sm">
        <thead className="bg-[var(--color-surface-raised)] text-left text-xs uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
          <tr>
            <th className="px-5 py-3">Scanner</th>
            <th className="px-5 py-3">Status</th>
            <th className="px-5 py-3">Started</th>
            <th className="px-5 py-3">Duration</th>
            <th className="px-5 py-3 text-right">Findings</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--color-border)]">
          {runs.map((run) => (
            <tr key={run.scan_id} className="transition-colors hover:bg-[var(--color-surface-raised)]">
              <td className="px-5 py-3.5">
                <span className="rounded px-1.5 py-0.5 text-xs font-semibold bg-[var(--color-accent-subtle)] text-[var(--color-accent)]">
                  {TOOL_LABELS[run.scanner_type] ?? run.scanner_type}
                </span>
              </td>
              <td className={`px-5 py-3.5 font-medium ${STATUS_STYLES[run.status] ?? "text-[var(--color-text-secondary)]"}`}>
                {run.status}
              </td>
              <td className="px-5 py-3.5 text-[var(--color-text-secondary)]">
                {relativeTime(run.started_at)}
              </td>
              <td className="px-5 py-3.5 tabular-nums text-[var(--color-text-secondary)]">
                {durationLabel(run.duration_ms)}
              </td>
              <td className="px-5 py-3.5 text-right tabular-nums font-semibold text-[var(--color-text-primary)]">
                {run.findings_count}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
