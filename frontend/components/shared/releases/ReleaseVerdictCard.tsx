/**
 * Top-of-page verdict summary for a pre-release scan.
 *
 * Verdict variants and copy are hardcoded for V1 — rules live in the backend
 * scoring step and the UI just reflects the resolved verdict. Do not add
 * client-side override logic.
 */

import type { ReleaseDetail } from "@/lib/client/releases-api"
import { Button } from "@/components/ui/Button"
import { Skeleton } from "@/components/ui/Skeleton"
import { relativeTime, shortenSha } from "./_helpers"

interface ReleaseVerdictCardProps {
  release: ReleaseDetail | null
  loading: boolean
  onCreateJiraTicket?: () => void
  onNotifySlack?: () => void
  onShareLink?: () => void
}

type Verdict = ReleaseDetail["verdict"]

interface VerdictStyle {
  container: string
  icon: string
  iconGlyph: string
}

const VERDICT_STYLES: Record<Verdict, VerdictStyle> = {
  no_go: {
    container: "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)]",
    icon:      "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]",
    iconGlyph: "×",
  },
  warn: {
    container: "border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)]",
    icon:      "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending)]",
    iconGlyph: "!",
  },
  go: {
    container: "border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)]",
    icon:      "bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok)]",
    iconGlyph: "✓",
  },
  pending: {
    container: "border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)]",
    icon:      "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending)]",
    iconGlyph: "⋯",
  },
  unknown: {
    container: "border-[var(--color-border)] bg-[var(--color-surface)]",
    icon:      "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]",
    iconGlyph: "?",
  },
}

function verdictTitle(release: ReleaseDetail): string {
  switch (release.verdict) {
    case "no_go":
      return `${release.blocker_count} critical findings — not recommended for release`
    case "warn":
      return `${release.warn_count} high findings — review before release`
    case "go":
      return "Cleared for release — no blockers"
    case "pending":
      return "Scan in progress…"
    case "unknown":
    default:
      return "Verdict unavailable — re-run scan to compute"
  }
}

const CARD_BASE = "rounded-lg border p-5"

export function ReleaseVerdictCard({
  release,
  loading,
  onCreateJiraTicket,
  onNotifySlack,
  onShareLink,
}: ReleaseVerdictCardProps) {
  if (loading) {
    return (
      <div className={`${CARD_BASE} border-[var(--color-border)] bg-[var(--color-surface)]`}>
        <div className="flex items-start gap-4">
          <Skeleton className="h-12 w-12 rounded-full" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-3 w-32" />
            <Skeleton className="h-5 w-72" />
            <Skeleton className="h-3 w-56" />
          </div>
        </div>
      </div>
    )
  }

  if (!release) {
    return (
      <div className={`${CARD_BASE} border-[var(--color-border)] bg-[var(--color-surface)] text-sm text-[var(--color-text-secondary)]`}>
        Run a scan to see the verdict.
      </div>
    )
  }

  const style = VERDICT_STYLES[release.verdict] ?? VERDICT_STYLES.unknown
  const refLabel = release.ref ?? release.short_sha
  const scannedAt = release.finished_at ?? release.started_at

  // Diff line is only meaningful when a baseline scan exists; without it we
  // can't meaningfully say "X new, Y persisted".
  const showDiffLine = Boolean(release.baseline_ref)
  const newCount = release.blockers_diff.filter((b) => b.diff_status === "new").length
  const persistedCount = release.blockers_diff.filter((b) => b.diff_status === "persisted").length

  const showJira = release.verdict !== "go" && onCreateJiraTicket
  const showSlack = Boolean(onNotifySlack)
  const showShare = Boolean(onShareLink)

  return (
    <div className={`${CARD_BASE} ${style.container}`}>
      <div className="flex items-start gap-4">
        <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-full text-xl font-semibold ${style.icon}`}>
          {style.iconGlyph}
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            Pre-release scan result
          </div>
          <div className="mt-1 text-base font-semibold text-[var(--color-text-primary)]">
            {verdictTitle(release)}
          </div>
          <div className="mt-1 text-sm text-[var(--color-text-secondary)]">
            <strong className="text-[var(--color-text-primary)]">{release.repo_id}</strong>
            {" @ "}
            <span className="font-mono">{refLabel}</span>
            {release.ref && (
              <>
                {" · "}
                <span className="font-mono">{release.short_sha}</span>
              </>
            )}
          </div>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--color-text-secondary)]">
            <span>Scanned {relativeTime(scannedAt)}</span>
            <span>{release.scanner_count} scanners ran</span>
            <span className="text-[var(--color-severity-critical)]">{release.blocker_count} blockers</span>
            {showDiffLine && (
              <span>
                Diff vs {release.baseline_ref}: {newCount} new, {persistedCount} persisted
              </span>
            )}
          </div>
          {(showJira || showSlack || showShare) && (
            <div className="mt-4 flex flex-wrap gap-2">
              {showJira && (
                <Button variant="secondary" size="xs" onClick={onCreateJiraTicket}>
                  Create Jira ticket
                </Button>
              )}
              {showSlack && (
                <Button variant="secondary" size="xs" onClick={onNotifySlack}>
                  Notify Slack
                </Button>
              )}
              {showShare && (
                <Button variant="secondary" size="xs" onClick={onShareLink}>
                  Share scan link
                </Button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
