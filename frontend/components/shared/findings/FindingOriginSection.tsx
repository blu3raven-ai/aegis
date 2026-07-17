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

// Matches the Details grid cell so the two adjacent metadata bands read as one
// designed surface. `wide` spans both columns for long values (file paths).
function Cell({
  label,
  value,
  wide,
  mono,
  title,
}: {
  label: string
  value: React.ReactNode
  wide?: boolean
  mono?: boolean
  title?: string
}) {
  return (
    <div className={wide ? "col-span-2 min-w-0" : "min-w-0"}>
      <dt className="font-mono text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">{label}</dt>
      <dd
        className={`mt-1 truncate text-[var(--color-text-primary)] ${
          mono ? "font-[family-name:var(--font-jetbrains-mono)] text-[11px]" : "text-sm"
        }`}
        title={title}
      >
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
      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
        {firstSeen && <Cell label="First seen" value={firstSeen} mono title={firstSeen} />}
        {finding.scanner && <Cell label="Scanner" value={scannerLabel ?? finding.scanner} />}
        {commit && (
          <Cell
            label="Introduced by commit"
            mono
            value={
              finding.introducedByPrUrl && /^https?:\/\//i.test(finding.introducedByPrUrl.trim()) ? (
                <a
                  href={finding.introducedByPrUrl.trim()}
                  target="_blank"
                  rel="noopener noreferrer"
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
          <Cell label="Introduced by" value={finding.introducedByAuthor} />
        )}
        {finding.filePath && (
          <Cell label="File path" wide mono value={finding.filePath} title={finding.filePath} />
        )}
      </dl>
    </section>
  )
}
