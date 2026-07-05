/**
 * Single row in the repos list table — composes coverage badge, scanner icons,
 * severity counts, and relative last-scan time.
 */
import Link from "next/link"
import { RepoCoverageBadge } from "./RepoCoverageBadge"
import { ScannerCoverageIcons } from "./ScannerCoverageIcons"
import type { RepoSummary } from "@/lib/client/repos-api"

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—"
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 2) return "just now"
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

interface RepoSummaryRowProps {
  repo: RepoSummary
}

export function RepoSummaryRow({ repo }: RepoSummaryRowProps) {
  const { critical, high, medium, low } = repo.findings_count_by_severity
  const hasFindings = critical + high + medium + low > 0
  const encodedId = encodeURIComponent(repo.repo_id)

  return (
    <tr className="transition-colors hover:bg-[var(--color-surface-raised)]">
      {/* Repo name */}
      <td className="px-5 py-4">
        <Link
          href={`/repos/${encodedId}`}
          className="font-medium text-[var(--color-text-primary)] hover:text-[var(--color-accent)] transition-colors"
        >
          {repo.repo}
        </Link>
        <span className="ml-2 text-xs font-normal text-[var(--color-text-secondary)]">{repo.org}</span>
      </td>

      {/* Coverage */}
      <td className="px-5 py-4">
        <RepoCoverageBadge status={repo.coverage_status} />
      </td>

      {/* Scanner coverage icons */}
      <td className="px-5 py-4">
        <ScannerCoverageIcons covered={repo.scanners_with_coverage} />
      </td>

      {/* Findings */}
      <td className="px-5 py-4 tabular-nums">
        {hasFindings ? (
          <span className="flex items-center gap-2 text-xs">
            {critical > 0 && (
              <span className="font-semibold text-[var(--color-severity-critical)]">{critical} C</span>
            )}
            {high > 0 && (
              <span className="font-semibold text-[var(--color-severity-high)]">{high} H</span>
            )}
            {medium > 0 && (
              <span className="text-[var(--color-severity-medium)]">{medium} M</span>
            )}
            {low > 0 && (
              <span className="text-[var(--color-text-secondary)]">{low} L</span>
            )}
          </span>
        ) : (
          <span className="text-xs text-[var(--color-text-secondary)]">—</span>
        )}
      </td>

      {/* Chains */}
      <td className="px-5 py-4 tabular-nums text-xs text-[var(--color-text-secondary)]">
        {repo.chains_count > 0 ? (
          <span className="font-semibold text-[var(--color-text-primary)]">{repo.chains_count}</span>
        ) : "—"}
      </td>

      {/* Last scan */}
      <td className="px-5 py-4 text-xs text-[var(--color-text-secondary)]">
        {relativeTime(repo.last_scanned_at)}
      </td>
    </tr>
  )
}
