import Link from "next/link"
import { RepoCoverageBadge } from "./RepoCoverageBadge"
import { RescanButton } from "./RescanButton"
import { ScannerCoverageIcons } from "./ScannerCoverageIcons"
import { SeverityCounts } from "@/components/shared/SeverityCounts"
import type { RepoSummary } from "@/lib/client/sources-api"

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

function shortSha(sha: string | null | undefined): string | null {
  if (!sha) return null
  return sha.length > 7 ? sha.slice(0, 7) : sha
}

interface RepoSummaryRowProps {
  repo: RepoSummary
}

export function RepoSummaryRow({ repo }: RepoSummaryRowProps) {
  const encodedId = encodeURIComponent(repo.repo_id)
  const ref = shortSha(repo.last_scanned_sha)

  return (
    <tr className="transition-colors hover:bg-[var(--color-surface-raised)]">
      <td className="px-5 py-4">
        <Link
          href={`/sources/${encodedId}`}
          className="font-medium text-[var(--color-text-primary)] hover:text-[var(--color-accent)] transition-colors"
        >
          {repo.repo}
        </Link>
        <span className="ml-2 text-xs font-normal text-[var(--color-text-secondary)]">{repo.org}</span>
      </td>

      <td className="px-5 py-4 tabular-nums">
        <SeverityCounts counts={repo.findings_count_by_severity} emptyLabel="no findings" />
      </td>

      <td className="px-5 py-4">
        <RepoCoverageBadge status={repo.coverage_status} />
      </td>

      <td className="px-5 py-4">
        <ScannerCoverageIcons covered={repo.scanners_with_coverage} />
      </td>

      <td className="px-5 py-4 text-xs text-[var(--color-text-secondary)]">
        <div className="flex flex-col gap-0.5">
          <span>{relativeTime(repo.last_scanned_at)}</span>
          {ref && (
            <span className="font-mono text-2xs text-[var(--color-text-tertiary)]">{ref}</span>
          )}
        </div>
      </td>

      <td className="px-5 py-4 text-right">
        <RescanButton repoId={repo.repo_id} lastScannedSha={repo.last_scanned_sha} />
      </td>
    </tr>
  )
}
