/**
 * "Blockers in this release" — diff between the current scan and its baseline.
 *
 * Renders NEW → PERSISTED → GONE in that order so a developer's eye lands on
 * the regressions first. FIXED rows are surfaced separately in
 * `ImprovementsList` and intentionally do not appear here.
 */

import Link from "next/link"
import type { BlockerDiffRow } from "@/lib/client/releases-api"
import { Card } from "@/components/ui/Card"
import {
  DIFF_PILL_BASE,
  DIFF_PILL_VARIANT,
  SEVERITY_LETTER,
  SEVERITY_TONE,
  severityKey,
  shortenSha,
  sortByDiffStatus,
} from "./_helpers"

interface BlockerDiffListProps {
  blockers: BlockerDiffRow[]
  emptyMessage: string
  baselineRef?: string | null
}

const CHIP_BASE =
  "inline-flex items-center rounded-full px-1.5 py-0.5 font-mono text-2xs font-semibold uppercase tracking-[0.14em]"

export function BlockerDiffList({ blockers, emptyMessage, baselineRef }: BlockerDiffListProps) {
  const visible = sortByDiffStatus(blockers).filter((b) => b.diff_status !== "fixed")
  const total = visible.length
  const newCount = visible.filter((b) => b.diff_status === "new").length
  const persistedCount = visible.filter((b) => b.diff_status === "persisted").length
  const hasBaseline = Boolean(baselineRef)

  return (
    <section className="flex flex-col gap-3">
      <header className="flex items-end justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            Blockers in this release
          </h2>
          {hasBaseline && (
            <p className="text-xs text-[var(--color-text-secondary)]">
              Compared against{" "}
              <span className="font-mono text-[var(--color-text-primary)]">{baselineRef}</span>{" "}
              at last scan
            </p>
          )}
        </div>
        {total > 0 && (
          <p className="text-xs text-[var(--color-text-secondary)] tabular-nums">
            {total} blockers · {newCount} new · {persistedCount} persisted
          </p>
        )}
      </header>

      {total === 0 ? (
        <Card padding="lg" className="text-center text-sm text-[var(--color-text-secondary)]">
          {emptyMessage}
        </Card>
      ) : (
        <Card padding="none" className="divide-y divide-[var(--color-border)]">
          {visible.map((row) => {
            const sevKey = severityKey(row.severity)
            const sevLetter = SEVERITY_LETTER[sevKey] ?? "?"
            const sevTone = SEVERITY_TONE[sevKey] ?? SEVERITY_TONE.info
            const pillVariant = DIFF_PILL_VARIANT[row.diff_status]
            const introSha = shortenSha(row.introduced_by_commit_sha)

            return (
              <div key={row.finding_id} className="flex items-center gap-4 px-5 py-3.5">
                <span className={`${DIFF_PILL_BASE} ${pillVariant}`}>
                  {row.diff_status}
                </span>
                <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-sm font-semibold ${sevTone}`}>
                  {sevLetter}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium text-[var(--color-text-primary)]">
                    {row.title}
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[var(--color-text-secondary)]">
                    {row.file_path && <span className="font-mono">{row.file_path}</span>}
                    {row.cve_id && (
                      <span className={`${CHIP_BASE} bg-[var(--color-accent-subtle)] text-[var(--color-accent)]`}>
                        {row.cve_id}
                      </span>
                    )}
                    {row.cwe_id && (
                      <span className={`${CHIP_BASE} bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]`}>
                        {row.cwe_id}
                      </span>
                    )}
                    {row.is_kev && (
                      <span className={`${CHIP_BASE} bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]`}>
                        KEV
                      </span>
                    )}
                    {row.epss_score != null && (
                      <span className={`${CHIP_BASE} bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending-text)]`}>
                        EPSS {Math.round(row.epss_score * 100)}%
                      </span>
                    )}
                    {introSha && (
                      <span>Introduced by <span className="font-mono">{introSha}</span></span>
                    )}
                  </div>
                </div>
                <Link
                  href={`/findings/${row.finding_id}`}
                  className="shrink-0 text-xs font-semibold text-[var(--color-accent)] hover:underline"
                >
                  View finding →
                </Link>
              </div>
            )
          })}
        </Card>
      )}
    </section>
  )
}
