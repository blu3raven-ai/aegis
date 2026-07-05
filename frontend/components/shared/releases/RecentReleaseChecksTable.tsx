/**
 * Cross-repo "Recent release checks" feed.
 *
 * "View all →" approximates the global release-checks view by linking to the
 * critical open findings filter for V1; a dedicated /releases list is out of
 * scope here and tracked separately.
 */

import Link from "next/link"
import type { ReleaseSummary } from "@/lib/client/releases-api"
import { relativeTime } from "./_helpers"
import { VERDICT_ICONS } from "./verdict-icons"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"

interface RecentReleaseChecksTableProps {
  releases: ReleaseSummary[]
  loading: boolean
}

function triggeredByLabel(release: ReleaseSummary): string {
  const { triggered_by } = release
  if (triggered_by.actor_type === "user") return `@${triggered_by.display_name} · CLI`
  if (triggered_by.actor_type === "ci") return `CI · ${triggered_by.display_name}`
  return triggered_by.display_name
}

function rowHref(release: ReleaseSummary): string {
  return `/sources/${encodeURIComponent(release.repo_id)}?tab=scans&scan_id=${encodeURIComponent(release.scan_id)}`
}

export function RecentReleaseChecksTable({ releases, loading }: RecentReleaseChecksTableProps) {
  return (
    <section className="flex flex-col gap-3">
      <header className="flex items-center justify-between gap-4">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          Recent release checks
        </h2>
        <Link
          href="/findings?state=open&severity=critical"
          className="text-xs font-semibold text-[var(--color-accent)] hover:underline"
        >
          View all →
        </Link>
      </header>

      {loading ? (
        <Card padding="none">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className={`flex items-center gap-4 px-5 py-3.5 ${i === 0 ? "" : "border-t border-[var(--color-border)]"}`}
            >
              <Skeleton className="h-8 w-8 rounded-full" />
              <div className="flex-1 space-y-1.5">
                <Skeleton className="h-3 w-32" />
                <Skeleton className="h-3 w-48" />
              </div>
              <Skeleton className="h-3 w-20" />
              <Skeleton className="h-3 w-16" />
            </div>
          ))}
        </Card>
      ) : releases.length === 0 ? (
        <Card padding="lg" className="text-center text-sm text-[var(--color-text-secondary)]">
          No recent release checks
        </Card>
      ) : (
        <Card padding="none" className="divide-y divide-[var(--color-border)]">
          {releases.map((release) => {
            const icon = VERDICT_ICONS[release.verdict] ?? VERDICT_ICONS.unknown
            const refLabel = release.ref ?? release.short_sha
            const blockerColor =
              release.blocker_count > 0
                ? "text-[var(--color-severity-critical-text)]"
                : "text-[var(--color-status-ok-text)]"
            const scannedAt = release.finished_at ?? release.started_at

            return (
              <Link
                key={release.scan_id}
                href={rowHref(release)}
                className="flex items-center gap-4 px-5 py-3.5 transition-colors hover:bg-[var(--color-surface-raised)]"
              >
                <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-sm font-semibold ${icon.tone}`}>
                  {icon.glyph}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium text-[var(--color-text-primary)]">
                    {release.repo}
                  </div>
                  <div className="truncate text-xs text-[var(--color-text-secondary)]">
                    <span className="font-mono">{refLabel}</span>
                    {release.ref && (
                      <>
                        {" · "}
                        <span className="font-mono">{release.short_sha}</span>
                      </>
                    )}
                  </div>
                </div>
                <div className="hidden shrink-0 text-xs text-[var(--color-text-secondary)] sm:block">
                  {triggeredByLabel(release)}
                </div>
                <div className="shrink-0 text-xs text-[var(--color-text-secondary)] tabular-nums">
                  <strong className={blockerColor}>{release.blocker_count}</strong>{" "}
                  {release.blocker_count === 1 ? "blocker" : "blockers"}
                </div>
                <div className="hidden shrink-0 text-xs text-[var(--color-text-tertiary)] tabular-nums sm:block">
                  {relativeTime(scannedAt)}
                </div>
              </Link>
            )
          })}
        </Card>
      )}
    </section>
  )
}
