/**
 * Header card for the repo detail page — shows name, coverage status,
 * last scan time, and top-level findings summary.
 */
import { RepoCoverageBadge } from "./RepoCoverageBadge"
import { ScannerCoverageIcons } from "./ScannerCoverageIcons"
import type { RepoDetail } from "@/lib/client/sources-api"
import { Card } from "@/components/ui/Card"

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "never"
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 2) return "just now"
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

interface RepoDetailHeroProps {
  repo: RepoDetail
}

export function RepoDetailHero({ repo }: RepoDetailHeroProps) {
  const { critical, high, medium, low } = repo.findings_count_by_severity
  const totalFindings = critical + high + medium + low

  return (
    <Card padding="none" className="px-6 py-5">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        {/* Title block */}
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-xl font-bold tracking-tight text-[var(--color-text-primary)] truncate">
              {repo.repo}
            </h1>
            <span className="text-sm text-[var(--color-text-secondary)]">{repo.org}</span>
          </div>

          {/* Meta row */}
          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-[var(--color-text-secondary)]">
            <RepoCoverageBadge status={repo.coverage_status} />
            <span>Last scan: {relativeTime(repo.last_scanned_at)}</span>
            {repo.last_scanned_sha && (
              <span className="font-mono">{repo.last_scanned_sha}</span>
            )}
          </div>
        </div>

        {/* Stats block */}
        <div className="flex flex-wrap items-center gap-4">
          {/* Scanner coverage */}
          <div className="flex flex-col items-end gap-1">
            <span className="text-xs text-[var(--color-text-secondary)]">Scanners</span>
            <ScannerCoverageIcons covered={repo.scanners_with_coverage} />
          </div>

          {/* Findings */}
          {totalFindings > 0 && (
            <div className="flex flex-col items-end gap-1">
              <span className="text-xs text-[var(--color-text-secondary)]">Findings</span>
              <div className="flex items-center gap-1.5 text-xs tabular-nums">
                {critical > 0 && (
                  <span className="font-bold text-[var(--color-severity-critical-text)]">{critical} C</span>
                )}
                {high > 0 && (
                  <span className="font-semibold text-[var(--color-severity-high-text)]">{high} H</span>
                )}
                {medium > 0 && (
                  <span className="text-[var(--color-severity-medium-text)]">{medium} M</span>
                )}
                {low > 0 && (
                  <span className="text-[var(--color-text-secondary)]">{low} L</span>
                )}
              </div>
            </div>
          )}

        </div>
      </div>
    </Card>
  )
}
