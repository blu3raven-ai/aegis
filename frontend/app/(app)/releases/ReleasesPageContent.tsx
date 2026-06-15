"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { listReleases, type ReleaseSummary } from "@/lib/client/releases-api"
import { relativeTime } from "@/components/shared/releases/_helpers"
import { Button } from "@/components/ui/Button"
import { SegmentedControl } from "@/components/ui/SegmentedControl"

type Verdict = ReleaseSummary["verdict"]

type VerdictFilter = "all" | Verdict

interface VerdictIcon {
  glyph: string
  tone: string
}

// Re-derived from RecentReleaseChecksTable to keep visual parity for verdict glyphs.
const VERDICT_ICONS: Record<Verdict, VerdictIcon> = {
  go:      { glyph: "✓", tone: "bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok)]" },
  no_go:   { glyph: "×", tone: "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]" },
  warn:    { glyph: "!", tone: "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending)]" },
  pending: { glyph: "•", tone: "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending)]" },
  unknown: { glyph: "—", tone: "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]" },
}

const VERDICT_FILTERS = [
  { id: "all"   as const, label: "All" },
  { id: "go"    as const, label: "GO" },
  { id: "warn"  as const, label: "WARN" },
  { id: "no_go" as const, label: "NO-GO" },
]

const CARD = "rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)]"

function triggeredByLabel(release: ReleaseSummary): string {
  const { triggered_by } = release
  if (triggered_by.actor_type === "user") return `@${triggered_by.display_name} · CLI`
  if (triggered_by.actor_type === "ci") return `CI · ${triggered_by.display_name}`
  return triggered_by.display_name
}

function rowHref(release: ReleaseSummary): string {
  return `/sources/${encodeURIComponent(release.repo_id)}?scan_id=${encodeURIComponent(release.scan_id)}`
}

export interface ReleasesPageContentProps {
  /** Optional callback fired with the total release count after each successful load. */
  onCountChange?: (count: number) => void
}

export function ReleasesPageContent({ onCountChange }: ReleasesPageContentProps = {}) {
  const [releases, setReleases] = useState<ReleaseSummary[]>([])
  const [listState, setListState] = useState<"loading" | "ok" | "error">("loading")
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>("all")

  const loadReleases = useCallback(async (verdict: VerdictFilter) => {
    setListState("loading")
    try {
      const filters = verdict === "all" ? {} : { verdict }
      const data = await listReleases(filters)
      setReleases(data.releases)
      onCountChange?.(data.releases.length)
      setListState("ok")
    } catch {
      setListState("error")
    }
  }, [onCountChange])

  useEffect(() => {
    void loadReleases(verdictFilter)
  }, [loadReleases, verdictFilter])

  const counts = useMemo(() => {
    const total = releases.length
    const blockers = releases.reduce((sum, r) => sum + r.blocker_count, 0)
    return { total, blockers }
  }, [releases])

  if (listState === "error") {
    return (
      <div className="px-6 py-5">
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-12 text-center">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">Could not load releases</p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            The backend may be unavailable. Check that the server is running and try again.
          </p>
          <div className="mt-4 inline-flex">
            <Button variant="secondary" size="sm" onClick={() => void loadReleases(verdictFilter)}>
              Retry
            </Button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-5 px-6 py-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <SegmentedControl
          ariaLabel="Filter by verdict"
          value={verdictFilter}
          onChange={(next) => setVerdictFilter(next as VerdictFilter)}
          options={VERDICT_FILTERS}
        />
        {listState === "ok" && releases.length > 0 && (
          <p className="text-xs tabular-nums text-[var(--color-text-secondary)]">
            {counts.total} {counts.total === 1 ? "scan" : "scans"} · {counts.blockers} {counts.blockers === 1 ? "blocker" : "blockers"}
          </p>
        )}
      </div>

      {listState === "loading" ? (
        <div className={CARD}>
          {[0, 1, 2, 3].map((i) => (
            <div
              key={i}
              className={`flex items-center gap-4 px-5 py-3.5 ${i === 0 ? "" : "border-t border-[var(--color-border)]"}`}
            >
              <div className="h-8 w-8 rounded-full bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
              <div className="flex-1 space-y-1.5">
                <div className="h-3 w-32 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
                <div className="h-3 w-48 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
              </div>
              <div className="h-3 w-24 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
              <div className="h-3 w-16 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
            </div>
          ))}
        </div>
      ) : releases.length === 0 ? (
        <ReleasesEmptyState filtered={verdictFilter !== "all"} onClearFilter={() => setVerdictFilter("all")} />
      ) : (
        <div className={`${CARD} divide-y divide-[var(--color-border)]`}>
          {releases.map((release) => {
            const icon = VERDICT_ICONS[release.verdict] ?? VERDICT_ICONS.unknown
            const refLabel = release.ref ?? release.short_sha
            const blockerColor =
              release.blocker_count > 0
                ? "text-[var(--color-severity-critical)]"
                : "text-[var(--color-status-ok)]"
            const scannedAt = release.finished_at ?? release.started_at

            return (
              <Link
                key={release.scan_id}
                href={rowHref(release)}
                className="flex items-center gap-4 px-5 py-3.5 transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset"
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
        </div>
      )}
    </div>
  )
}

function ReleasesEmptyState({
  filtered,
  onClearFilter,
}: {
  filtered: boolean
  onClearFilter: () => void
}) {
  if (filtered) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 py-20 text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]">
          <svg className="h-8 w-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
          </svg>
        </div>
        <div className="flex flex-col gap-1">
          <p className="text-base font-semibold text-[var(--color-text-primary)]">No releases match this filter</p>
          <p className="max-w-sm text-sm text-[var(--color-text-secondary)]">
            Try a different verdict, or clear the filter to see all recent pre-release scans.
          </p>
        </div>
        <Button variant="secondary" size="md" onClick={onClearFilter}>
          Clear filter
        </Button>
      </div>
    )
  }

  return (
    <div className="flex flex-col items-center justify-center gap-4 py-20 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-[var(--color-accent-subtle)] text-[var(--color-accent)]">
        <svg className="h-8 w-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M9 12.75 11.25 15 15 9.75M3.75 9.75h16.5M3.75 9.75A2.25 2.25 0 0 1 6 7.5h12a2.25 2.25 0 0 1 2.25 2.25v9A2.25 2.25 0 0 1 18 21H6a2.25 2.25 0 0 1-2.25-2.25v-9ZM7.5 7.5V5.25A2.25 2.25 0 0 1 9.75 3h4.5a2.25 2.25 0 0 1 2.25 2.25V7.5" />
        </svg>
      </div>
      <div className="flex flex-col gap-1">
        <p className="text-base font-semibold text-[var(--color-text-primary)]">No release scans yet</p>
        <p className="max-w-md text-sm text-[var(--color-text-secondary)]">
          Trigger a pre-release scan from any repository to see verdicts, blockers, and diff against main collected here.
        </p>
      </div>
      <Link
        href="/sources"
        className="inline-flex h-9 items-center gap-1.5 rounded-md bg-[var(--color-accent)] px-3.5 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)]"
      >
        Trigger a release scan
        <svg className="h-3.5 w-3.5 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M5 12h14M13 5l7 7-7 7" />
        </svg>
      </Link>
    </div>
  )
}
