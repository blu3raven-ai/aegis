/**
 * "Origin" block for the findings detail drawer.
 *
 * Renders whichever provenance fields the finding payload carries: first
 * seen, scanner, introducing commit/PR, file path. Rows render only when
 * the underlying field is populated — no fetching happens here.
 */

import type { FindingRow } from "@/lib/shared/findings/row-mapper"

interface FindingOriginSectionProps {
  finding: Pick<
    FindingRow,
    "firstSeen" | "scanner" | "filePath" | "introducedByCommit" | "introducedByAuthor" | "introducedByPrUrl"
  >
  scannerLabel?: string
}

function formatFirstSeen(iso: string | undefined): string | null {
  if (!iso) return null
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return null
  const year = date.getUTCFullYear()
  const month = String(date.getUTCMonth() + 1).padStart(2, "0")
  const day = String(date.getUTCDate()).padStart(2, "0")
  return `${year}-${month}-${day}`
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1">
      <dt className="text-sm text-[var(--color-text-secondary)]">{label}</dt>
      <dd className="text-sm font-medium text-[var(--color-text-primary)] text-right truncate font-[family-name:var(--font-jetbrains-mono)]">
        {value}
      </dd>
    </div>
  )
}

export function FindingOriginSection({ finding, scannerLabel }: FindingOriginSectionProps) {
  const firstSeen = formatFirstSeen(finding.firstSeen)
  const commit = finding.introducedByCommit
    ? finding.introducedByCommit.slice(0, 7)
    : null
  const hasAny =
    firstSeen != null ||
    finding.scanner != null ||
    finding.filePath != null ||
    commit != null ||
    finding.introducedByAuthor != null

  if (!hasAny) return null

  return (
    <section aria-labelledby="finding-origin-title">
      <h3
        id="finding-origin-title"
        className="text-base font-semibold text-[var(--color-text-primary)]"
      >
        Origin
      </h3>
      <dl className="mt-3 divide-y divide-[var(--color-border)]">
        {firstSeen && <Row label="First seen" value={firstSeen} />}
        {finding.scanner && (
          <Row label="Scanner" value={scannerLabel ?? finding.scanner} />
        )}
        {commit && (
          <Row
            label="Introduced by commit"
            value={
              finding.introducedByPrUrl ? (
                <a
                  href={finding.introducedByPrUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="text-[var(--color-accent)] underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
                >
                  {commit}
                </a>
              ) : (
                commit
              )
            }
          />
        )}
        {finding.introducedByAuthor && (
          <Row label="Introduced by" value={finding.introducedByAuthor} />
        )}
        {finding.filePath && <Row label="File path" value={finding.filePath} />}
      </dl>
    </section>
  )
}
