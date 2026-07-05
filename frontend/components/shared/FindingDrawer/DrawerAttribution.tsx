// components/shared/FindingDrawer/DrawerAttribution.tsx

import { relativeTime } from "@/lib/shared/relative-time"
import { Card } from "@/components/ui/Card"

export interface AttributionFields {
  introduced_by_commit_sha: string | null | undefined
  introduced_by_author: string | null | undefined
  introduced_at: string | null | undefined
  introduced_by_pr_url: string | null | undefined
}

export { relativeTime }

/**
 * Renders the commit/PR attribution row inside a finding drawer.
 * Returns null when none of the four fields are populated — callers
 * don't need to guard themselves.
 */
export function DrawerAttribution({ fields }: { fields: AttributionFields }) {
  const { introduced_by_commit_sha, introduced_by_author, introduced_at, introduced_by_pr_url } =
    fields

  const hasAny =
    introduced_by_commit_sha || introduced_by_author || introduced_at || introduced_by_pr_url

  if (!hasAny) return null

  const shortSha = introduced_by_commit_sha ? introduced_by_commit_sha.slice(0, 7) : null

  return (
    <Card as="section" padding="none" className="rounded-xl">
      <div className="px-4 pt-4 pb-2">
        <p className="text-2xs font-semibold uppercase tracking-[0.6px] text-[var(--color-text-tertiary)]">
          Introduced by
        </p>
      </div>
      <div className="px-4 pb-4">
        <div className="flex flex-wrap items-baseline gap-1.5">
          {shortSha && (
            <span className="font-[family-name:var(--font-jetbrains-mono)] text-sm font-medium text-[var(--color-text-primary)]">
              {shortSha}
            </span>
          )}
          {introduced_by_author && (
            <>
              {shortSha && (
                <span className="text-[var(--color-text-tertiary)] text-[11px]">·</span>
              )}
              <span className="text-[11px] text-[var(--color-text-secondary)]">
                {introduced_by_author}
              </span>
            </>
          )}
          {introduced_at && (
            <>
              <span className="text-[var(--color-text-tertiary)] text-[11px]">·</span>
              <span className="text-[11px] text-[var(--color-text-secondary)]">
                {relativeTime(introduced_at)}
              </span>
            </>
          )}
        </div>
        {introduced_by_pr_url && (
          <a
            href={introduced_by_pr_url}
            target="_blank"
            rel="noreferrer"
            className="mt-1.5 inline-flex items-center gap-1 text-[11px] font-semibold text-[var(--color-accent)] underline underline-offset-2 hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
          >
            {/* "→ PR" label derived from URL when possible */}
            {extractPrLabel(introduced_by_pr_url)}
          </a>
        )}
      </div>
    </Card>
  )
}

function extractPrLabel(url: string): string {
  try {
    // Matches GitHub-style /pull/123 paths
    const match = url.match(/\/pull\/(\d+)/)
    if (match) return `→ PR #${match[1]}`
  } catch {
    // fall through
  }
  return `→ ${url}`
}
