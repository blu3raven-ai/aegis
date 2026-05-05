import type { SecretFinding } from "@/lib/shared/secrets/types"
import { ReviewActionButtons } from "@/app/(app)/secrets/_components/review-action-buttons"
import {
  findingUiIdentity,
  reviewStatusLabel,
  reviewTone,
} from "@/lib/shared/secrets/dashboard-utils"

export interface NewKeyReviewQueueRow {
  finding: SecretFinding
  occurrenceCount: number
  commitDate: Date | null
}

export interface TimelineEntry {
  key: string
  label: string
  count: number
  newCount: number
  confirmedCount: number
  falsePositiveCount: number
  actionTakenCount: number
}


export function StatCard({
  label,
  value,
  note,
  valueClass,
}: {
  label: string
  value: string
  note: string
  valueClass: string
}) {
  return (
    <div className="flex flex-col rounded-3xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-4 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        {label}
      </p>
      <p className={`mt-3 text-4xl font-semibold leading-none tabular-nums ${valueClass}`}>{value}</p>
      <p className="mt-2 text-sm text-[var(--color-text-secondary)]">{note}</p>
    </div>
  )
}

export function NewKeyReviewQueue({
  rows,
  remainingCount,
  onConfirm,
  onFalsePositive,
  onActionTaken,
  onPreview,
}: {
  rows: NewKeyReviewQueueRow[]
  remainingCount: number
  onConfirm: (finding: SecretFinding) => void
  onFalsePositive: (finding: SecretFinding) => void
  onActionTaken: (finding: SecretFinding) => void
  onPreview: (finding: SecretFinding) => void
}) {
  return (
    <div className="rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">New Key Review Queue</p>
          <h3 className="mt-2 text-xl font-semibold text-[var(--color-text-primary)]">Classify the Next Keys</h3>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            Prioritizes repeated new keys left to annotate, then the newest commit evidence in the current view.
          </p>
        </div>
        <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1 text-xs font-medium text-[var(--color-text-secondary)]">
          {remainingCount} remaining
        </span>
      </div>

      {rows.length === 0 ? (
        <div className="mt-5 flex min-h-28 items-center justify-center rounded-2xl border border-dashed border-[var(--color-border)] text-sm text-[var(--color-text-secondary)]">
          No new keys in the current view.
        </div>
      ) : (
        <div className="mt-5 space-y-2">
          {rows.map(({ finding, occurrenceCount, commitDate }) => {
            const commitLabel = finding.commit ? finding.commit.slice(0, 7) : "no commit"
            const dateLabel = commitDate
              ? commitDate.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })
              : "date unknown"
            return (
              <div
                key={findingUiIdentity(finding)}
                className="grid gap-3 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4 lg:grid-cols-[minmax(0,1fr)_auto]"
              >
                <button type="button" onClick={() => onPreview(finding)} className="min-w-0 text-left">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded-full border border-[var(--color-accent)]/20 bg-[var(--color-accent-subtle)] px-2.5 py-1 text-xs font-semibold text-[var(--color-accent)]">
                      new
                    </span>
                    <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)]">
                      {occurrenceCount} occurrence{occurrenceCount === 1 ? "" : "s"}
                    </span>
                    <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)]">
                      {finding.detector}
                    </span>
                    <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)]">
                      {finding.source}
                    </span>
                  </div>
                  <p className="mt-3 truncate text-sm font-semibold text-[var(--color-text-primary)]" title={`${finding.organization}/${finding.repository}`}>
                    {finding.organization}/{finding.repository}
                  </p>
                  <p className="mt-1 truncate font-mono text-xs text-[var(--color-text-primary)]" title={finding.secretSnippet}>
                    {finding.secretSnippet}
                  </p>
                  <p className="mt-2 truncate font-mono text-xs text-[var(--color-text-secondary)]">
                    {commitLabel} · {dateLabel}
                    {finding.filePath ? ` · ${finding.filePath}${finding.line ? `:${finding.line}` : ""}` : ""}
                  </p>
                </button>

                <div className="flex flex-wrap items-center gap-2 lg:justify-end">
                  <button
                    type="button"
                    onClick={() => onPreview(finding)}
                    className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-xs font-semibold text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)]"
                  >
                    Preview
                  </button>
                  <ReviewActionButtons
                    size="sm"
                    onConfirm={() => onConfirm(finding)}
                    onFalsePositive={() => onFalsePositive(finding)}
                    onActionTaken={() => onActionTaken(finding)}
                  />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export function CommitTimelineChart({
  entries,
  unknownCount,
}: {
  entries: TimelineEntry[]
  unknownCount: number
}) {
  if (entries.length === 0) {
    return (
      <div className="flex min-h-36 items-center justify-center rounded-xl border border-dashed border-[var(--color-border)] text-sm text-[var(--color-text-secondary)]">
        No commit dates found for the selected view.
      </div>
    )
  }

  const max = Math.max(...entries.map((entry) => entry.count), 1)
  const total = entries.reduce((sum, entry) => sum + entry.count, 0)

  return (
    <div className="space-y-4">
      <div className="rounded-3xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-5">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-semibold text-[var(--color-text-primary)]">Commit month trend</p>
            <p className="mt-1 text-xs text-[var(--color-text-secondary)]">When secrets entered repository history, split by review status.</p>
          </div>
          <div className="flex flex-wrap justify-end gap-2 text-xs text-[var(--color-text-secondary)]">
            <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1 font-medium text-[var(--color-text-secondary)]">
              {total} keys
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1">
              <span className="h-2 w-2 rounded-full bg-orange-500" /> New
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1">
              <span className="h-2 w-2 rounded-full bg-red-500" /> Confirmed
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1">
              <span className="h-2 w-2 rounded-full bg-emerald-500" /> False positive
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1">
              <span className="h-2 w-2 rounded-full bg-blue-500" /> Action taken
            </span>
          </div>
        </div>
        <div className="space-y-3">
          {entries.map((entry) => {
            const width = Math.max((entry.count / max) * 100, entry.count ? 4 : 0)
            const pct = total > 0 ? Math.round((entry.count / total) * 100) : 0
            const newWidth = entry.count > 0 ? (entry.newCount / entry.count) * 100 : 0
            const confirmedWidth = entry.count > 0 ? (entry.confirmedCount / entry.count) * 100 : 0
            const falsePositiveWidth = entry.count > 0 ? (entry.falsePositiveCount / entry.count) * 100 : 0
            const actionTakenWidth = entry.count > 0 ? (entry.actionTakenCount / entry.count) * 100 : 0
            return (
              <div key={entry.key} className="grid grid-cols-[7.5rem_minmax(0,1fr)_4.5rem] items-center gap-3 text-sm">
                <span className="truncate text-[var(--color-text-primary)]" title={entry.label}>
                  {entry.label}
                </span>
                <div className="h-3 overflow-hidden rounded-full bg-[var(--color-border)]">
                  <div
                    className="flex h-3 overflow-hidden rounded-full"
                    style={{ width: `${width}%` }}
                    title={`${entry.newCount} new, ${entry.confirmedCount} confirmed, ${entry.falsePositiveCount} false positive, ${entry.actionTakenCount} action taken`}
                  >
                    {entry.newCount > 0 && <span className="h-full bg-orange-500" style={{ width: `${newWidth}%` }} />}
                    {entry.confirmedCount > 0 && <span className="h-full bg-red-500" style={{ width: `${confirmedWidth}%` }} />}
                    {entry.falsePositiveCount > 0 && <span className="h-full bg-emerald-500" style={{ width: `${falsePositiveWidth}%` }} />}
                    {entry.actionTakenCount > 0 && <span className="h-full bg-blue-500" style={{ width: `${actionTakenWidth}%` }} />}
                  </div>
                </div>
                <span className="text-right font-mono text-xs text-[var(--color-text-secondary)]">
                  {entry.count} ({pct}%)
                </span>
              </div>
            )
          })}
        </div>
        {unknownCount > 0 && (
          <p className="mt-4 text-xs text-amber-600 dark:text-amber-300">
            {unknownCount} key{unknownCount === 1 ? "" : "s"} without commit date hidden from chart.
          </p>
        )}
      </div>
    </div>
  )
}

export function BreakdownBarList({
  entries,
  tone,
}: {
  entries: Array<{ label: string; count: number }>
  tone: string
}) {
  if (entries.length === 0) {
    return (
      <div className="flex min-h-32 items-center justify-center rounded-xl border border-dashed border-[var(--color-border)] text-sm text-[var(--color-text-secondary)]">
        No findings yet
      </div>
    )
  }

  const total = entries.reduce((sum, entry) => sum + entry.count, 0)

  return (
    <div className="space-y-3">
      {entries.map((entry) => (
        <BreakdownBar
          key={entry.label}
          label={entry.label}
          count={entry.count}
          pct={total > 0 ? Math.round((entry.count / total) * 100) : 0}
          tone={tone}
        />
      ))}
    </div>
  )
}

function BreakdownBar({
  label,
  count,
  pct,
  tone,
}: {
  label: string
  count: number
  pct: number
  tone: string
}) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-3 text-sm">
        <span className="truncate text-[var(--color-text-primary)]" title={label}>
          {label}
        </span>
        <span className="shrink-0 text-xs text-[var(--color-text-secondary)]">
          {count} ({pct}%)
        </span>
      </div>
      <div className="h-2.5 rounded-full bg-[var(--color-surface-raised)]">
        <div className={`h-2.5 rounded-full ${tone}`} style={{ width: `${Math.max(pct, count ? 6 : 0)}%` }} />
      </div>
    </div>
  )
}
