/**
 * "Improvements in this release" — issues present on the baseline branch but
 * resolved in the current scan. Hidden entirely when empty since the section
 * has no informational value without rows.
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
} from "./_helpers"

interface ImprovementsListProps {
  improvements: BlockerDiffRow[]
}

const CHIP_BASE =
  "inline-flex items-center rounded-full px-1.5 py-0.5 font-mono text-2xs font-semibold uppercase tracking-[0.14em]"

export function ImprovementsList({ improvements }: ImprovementsListProps) {
  if (improvements.length === 0) return null

  const count = improvements.length

  return (
    <section className="flex flex-col gap-3">
      <header className="flex items-end justify-between gap-4">
        <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
          Improvements in this release
        </h2>
        <p className="text-xs text-[var(--color-text-secondary)] tabular-nums">
          {count} issues from main are fixed here
        </p>
      </header>

      <Card padding="none" className="divide-y divide-[var(--color-border)]">
        {improvements.map((row) => {
          const sevKey = severityKey(row.severity)
          const sevLetter = SEVERITY_LETTER[sevKey] ?? "?"
          const sevTone = SEVERITY_TONE[sevKey] ?? SEVERITY_TONE.info
          const fixSha = shortenSha(row.introduced_by_commit_sha)

          return (
            <div key={row.finding_id} className="flex items-center gap-4 px-5 py-3.5">
              <span className={`${DIFF_PILL_BASE} ${DIFF_PILL_VARIANT.fixed}`}>
                fixed
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
                  {fixSha && (
                    <span>Fixed in <span className="font-mono">{fixSha}</span></span>
                  )}
                </div>
              </div>
              <Link
                href={`/findings?finding=${row.finding_id}`}
                className="shrink-0 text-xs font-semibold text-[var(--color-accent)] hover:underline"
              >
                View finding →
              </Link>
            </div>
          )
        })}
      </Card>
    </section>
  )
}
