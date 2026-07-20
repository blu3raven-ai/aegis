"use client"

import { useRef, useState } from "react"
import { AlertTriangle, Loader2, Maximize2, Minus, X } from "lucide-react"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { cn } from "@/lib/shared/utils"

interface RunProgress {
  expectedRepos?: number | null
  scannedRepos?: number
  finishedRepos?: number
  percent?: number
  currentRepo?: string | null
  stage?: string
  currentClassifying?: string | null
  ingestedRepos?: number
  expectedIngest?: number
}

interface ScanRunningBannerProps {
  organization: string
  status: string
  progress?: RunProgress | null
  logTail?: string[]
  startedAt: string | null
  createdAt?: string | null
  nowMs: number
  commandLabel: string
  scanLabel?: string
  /** Extra stage mappings merged with defaults (e.g. { classifying: "Classifying findings" }) */
  extraStages?: Record<string, string>
  /** Show "sync: docker logs" indicator */
  showSyncLabel?: boolean
  /** Override progress capping logic — return the adjusted progress value */
  progressOverride?: (raw: number, progress: RunProgress | null | undefined, isInitializing: boolean) => number
  /** Per-scanner status counts, to show how many are queued vs running vs done. */
  runCounts?: { total: number; queued: number; running: number; completed: number; failed: number }
  /** Label of the scanner the repo count belongs to — the bar % is the overall
   *  average across scanners, so the repo count is scoped to avoid confusion. */
  activeScannerLabel?: string
  /** When set, renders an inline Cancel control so the scan can be stopped
   *  from anywhere the banner is shown, not only the source detail page. */
  onCancel?: () => void
  /** Hide this banner without stopping the scan — an always-available escape
   *  hatch so a lingering or unwanted banner can be closed. */
  onDismiss?: () => void
  isCancelling?: boolean
}

const ACTIVE_STATUSES = new Set(["queued", "running", "ingesting"])
const VISIBLE_STATUSES = new Set(["queued", "running", "ingesting", "failed"])

/** "1 of 3 scanners" style progress through the scan's scanners (failures
 *  count as finished, and are called out separately when present). */
function scannerSummary(c: NonNullable<ScanRunningBannerProps["runCounts"]>): string {
  const finished = c.completed + c.failed
  const base = `${finished} of ${c.total} scanner${c.total === 1 ? "" : "s"}`
  return c.failed ? `${base} · ${c.failed} failed` : base
}

function formatElapsed(startedAt: string | null, nowMs: number): string {
  if (!startedAt) return "0s"
  const elapsed = Math.max(0, Math.round((nowMs - new Date(startedAt).getTime()) / 1000))
  if (elapsed < 60) return `${elapsed}s`
  const m = Math.floor(elapsed / 60)
  const s = elapsed % 60
  return s > 0 ? `${m}m ${s}s` : `${m}m`
}

function elapsedSeconds(startedAt: string | null, nowMs: number): number {
  if (!startedAt) return 0
  return Math.max(0, Math.round((nowMs - new Date(startedAt).getTime()) / 1000))
}

const DEFAULT_STAGES: Record<string, string> = {
  queued: "Queued",
  scanning: "Scanning",
  detonating: "Detonating in sandbox",
  ingesting: "Saving results",
  classifying: "Analysing findings",
}

type Tone = "running" | "queued" | "failed"

function toneClasses(tone: Tone): { dot: string; pulse: boolean; text: string } {
  if (tone === "failed") {
    return {
      dot: "bg-[var(--color-severity-critical)]",
      pulse: false,
      text: "text-[var(--color-severity-critical-text)]",
    }
  }
  if (tone === "queued") {
    return {
      dot: "bg-[var(--color-severity-medium)]",
      pulse: true,
      text: "text-[var(--color-text-primary)]",
    }
  }
  return {
    dot: "bg-[var(--color-accent)]",
    pulse: true,
    text: "text-[var(--color-text-primary)]",
  }
}

export function ScanRunningBanner({
  organization,
  status,
  progress,
  logTail,
  startedAt,
  nowMs,
  commandLabel,
  scanLabel,
  createdAt,
  extraStages,
  showSyncLabel,
  progressOverride,
  runCounts,
  activeScannerLabel,
  onCancel,
  onDismiss,
  isCancelling,
}: ScanRunningBannerProps) {
  const highestProgressRef = useRef<number>(0)
  // Minimize (≠ dismiss): collapse to a compact bar so the user can keep
  // working while the scan stays pinned and live-updating. State lives here so
  // it persists for the scan's lifetime (the provider keeps this mounted).
  const [minimized, setMinimized] = useState(false)

  if (!VISIBLE_STATUSES.has(status)) return null

  const isFailed = status === "failed"
  const isQueued = status === "queued"
  const isActive = ACTIVE_STATUSES.has(status)

  const progressValue = progress?.percent ?? 0
  const timeRef = startedAt ?? createdAt ?? null
  const elapsed = formatElapsed(timeRef, nowMs)
  const elapsedSec = elapsedSeconds(timeRef, nowMs)
  const scannedRepos = progress?.scannedRepos ?? 0
  const finishedRepos = progress?.finishedRepos ?? 0
  const expectedRepos = progress?.expectedRepos
  const currentRepo = progress?.currentRepo
  const currentClassifying = progress?.currentClassifying ?? null
  const hasRepoActivity = scannedRepos > 0 || finishedRepos > 0 || Boolean(currentRepo)
  const isInitializing = status === "running" && !hasRepoActivity

  const rawDisplayProgress = progressOverride
    ? progressOverride(progressValue, progress, isInitializing)
    : isInitializing ? Math.max(2, progressValue) : progressValue

  if (!isFailed) {
    highestProgressRef.current = Math.max(highestProgressRef.current, rawDisplayProgress)
  }
  const displayProgress = highestProgressRef.current
  const repoCountLabel = expectedRepos
    ? `${String(finishedRepos).padStart(String(expectedRepos).length, "0")}/${expectedRepos}`
    : String(finishedRepos)

  const allStages = { ...DEFAULT_STAGES, ...extraStages }
  const stageLabel = isFailed
    ? "Failed"
    : isQueued
    ? "Queued"
    : (allStages[progress?.stage ?? ""] ?? "Running")

  const tone: Tone = isFailed ? "failed" : isQueued ? "queued" : "running"
  const cfg = toneClasses(tone)

  const StatusIcon = isFailed ? AlertTriangle : Loader2
  const chipClass = isFailed
    ? "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]"
    : isQueued
    ? "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending-text)]"
    : "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"

  const headline = isFailed
    ? `${scanLabel ?? "Scan"} failed for ${organization}`
    : isQueued
    ? `Waiting for runner to pick up scanning for ${organization}`
    : isInitializing
    ? "Preparing scanner"
    : `Scanning in progress for ${organization}`

  const recentLogLines = (logTail ?? []).slice(-4)
  // No meaningful percent yet while queued or spinning up — show an
  // indeterminate bar instead of a misleading full bar at 0%.
  const isIndeterminate = isActive && (isQueued || isInitializing)
  const progressFillWidth = Math.min(100, isActive ? Math.max(3, displayProgress) : displayProgress)
  const barColor = isFailed
    ? "bg-[var(--color-severity-critical)]"
    : isQueued
    ? "bg-[var(--color-state-pending)]"
    : "bg-[var(--color-accent)]"

  if (minimized) {
    return (
      <Card
        padding="none"
        role="status"
        aria-live="polite"
        className="overflow-hidden rounded-2xl shadow-[var(--shadow-nav)]"
      >
        <div className="flex items-center gap-2 px-3 py-2 text-sm text-[var(--color-text-primary)]">
          <span className={cn("grid h-7 w-7 shrink-0 place-items-center rounded-lg", chipClass)}>
            <StatusIcon
              className={cn("h-4 w-4", !isFailed && "motion-safe:animate-spin")}
              aria-hidden="true"
            />
          </span>
          <p className="min-w-0 flex-1 truncate text-xs font-medium" title={headline}>
            {headline}
          </p>
          {!isIndeterminate && !isFailed && (
            <span className="shrink-0 text-xs tabular-nums text-[var(--color-text-secondary)]">
              {Math.round(displayProgress)}%
            </span>
          )}
          <span className="shrink-0 text-xs tabular-nums text-[var(--color-text-tertiary)]">{elapsed}</span>
          <Button
            variant="ghost"
            size="xs"
            iconOnly
            aria-label="Restore scan progress"
            onClick={() => setMinimized(false)}
            leadingIcon={<Maximize2 className="h-3.5 w-3.5" />}
          />
          {onCancel && isActive && (
            <Button
              variant="ghost"
              size="xs"
              iconOnly
              aria-label="Cancel scan"
              onClick={onCancel}
              disabled={isCancelling}
              leadingIcon={<X className="h-3.5 w-3.5" strokeWidth={2.5} />}
              className="text-[var(--color-severity-critical-text)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical-text)]"
            />
          )}
          {onDismiss && (
            <Button
              variant="ghost"
              size="xs"
              iconOnly
              aria-label="Dismiss"
              onClick={onDismiss}
              leadingIcon={<X className="h-3.5 w-3.5" />}
              className="text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)]"
            />
          )}
        </div>
      </Card>
    )
  }

  return (
    <Card
      padding="none"
      role="status"
      aria-live="polite"
      className="overflow-hidden rounded-2xl border border-[var(--color-border)] shadow-[var(--shadow-nav)]"
    >
      <div className="space-y-4 p-4 text-sm text-[var(--color-text-primary)]">
        <div className="flex items-start gap-3">
          <span className={cn("grid h-9 w-9 shrink-0 place-items-center rounded-xl", chipClass)}>
            <StatusIcon
              className={cn("h-[18px] w-[18px]", !isFailed && "motion-safe:animate-spin")}
              aria-hidden="true"
            />
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex items-center justify-between gap-2">
              <span className={cn("font-mono text-2xs font-semibold uppercase tracking-[0.14em]", cfg.text)}>
                {stageLabel}
              </span>
              <span className="shrink-0 text-xs tabular-nums text-[var(--color-text-secondary)]">
                {elapsed}
              </span>
            </div>
            <p className="mt-0.5 line-clamp-2 text-sm text-[var(--color-text-primary)]" title={headline}>
              {headline}
            </p>
            {tone === "running" && (
              <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
                You can keep working. We will notify you when it is done.
              </p>
            )}
            {progress?.stage === "detonating" && (
              <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
                Running untrusted code in an isolated sandbox. This can take a few minutes.
              </p>
            )}
          </div>
          <div className="-mr-1 -mt-1 flex shrink-0 items-center">
            {isActive && (
              <Button
                variant="ghost"
                size="xs"
                iconOnly
                aria-label="Minimize scan progress"
                onClick={() => setMinimized(true)}
                leadingIcon={<Minus className="h-3.5 w-3.5" />}
                className="text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)]"
              />
            )}
            {onDismiss && (
              <Button
                variant="ghost"
                size="xs"
                iconOnly
                aria-label="Dismiss"
                onClick={onDismiss}
                leadingIcon={<X className="h-3.5 w-3.5" />}
                className="text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)]"
              />
            )}
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <span
              className="relative block h-2 flex-1 overflow-hidden rounded-full bg-[var(--color-border)]"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={isIndeterminate ? undefined : Math.round(displayProgress)}
              aria-label="Scan progress"
            >
              {isIndeterminate ? (
                <span
                  className={cn(
                    "absolute inset-y-0 left-0 w-1/3 rounded-full motion-safe:animate-[scan-indeterminate_1.4s_ease-in-out_infinite]",
                    barColor,
                  )}
                />
              ) : (
                <span
                  className={cn("absolute inset-y-0 left-0 rounded-full transition-[width] duration-700 ease-out", barColor)}
                  style={{ width: `${progressFillWidth}%` }}
                />
              )}
            </span>
            {isIndeterminate ? (
              <span className="w-10 shrink-0 text-right text-xs text-[var(--color-text-tertiary)]">···</span>
            ) : (
              <span className="w-10 shrink-0 text-right text-xs tabular-nums text-[var(--color-text-secondary)]">
                {Math.round(displayProgress)}%
              </span>
            )}
          </div>

          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--color-text-secondary)]">
            {runCounts && runCounts.total > 0 && <span>{scannerSummary(runCounts)}</span>}
            {currentClassifying ? (
              <span>
                Classified <span className="font-mono text-[var(--color-text-primary)]">{currentClassifying}</span>
              </span>
            ) : progress?.stage === "ingesting" && progress?.expectedIngest ? (
              <span>
                Ingested{" "}
                <span className="tabular-nums text-[var(--color-text-primary)]">
                  {String(progress.ingestedRepos ?? 0).padStart(String(progress.expectedIngest).length, "0")}/{progress.expectedIngest}
                </span>
              </span>
            ) : hasRepoActivity ? (
              <span>
                {activeScannerLabel ? `${activeScannerLabel}: ` : "Repositories "}
                <span className="tabular-nums text-[var(--color-text-primary)]">{repoCountLabel}</span>
                {activeScannerLabel ? " repos" : ""}
              </span>
            ) : null}
            {showSyncLabel && <span>Sync: docker logs</span>}
            {currentRepo && !currentClassifying && (
              <span className="truncate" title={currentRepo}>
                Current scan: <span className="font-mono text-[var(--color-text-primary)]">{currentRepo}</span>
              </span>
            )}
          </div>
        </div>

        {commandLabel && (
          <p
            className="truncate border-t border-[var(--color-border)] pt-3 font-mono text-[12px] text-[var(--color-text-tertiary)]"
            title={commandLabel}
          >
            {commandLabel}
          </p>
        )}

        {recentLogLines.length > 0 && (
          <div className="space-y-1 border-t border-[var(--color-border)] pt-3">
            <p className="text-xs font-medium text-[var(--color-text-secondary)]">Activity</p>
            <ul className="space-y-0.5">
              {recentLogLines.map((line, index) => (
                <li
                  key={`${index}-${line}`}
                  className="truncate font-mono text-[12px] text-[var(--color-text-secondary)]"
                  title={line}
                >
                  {line}
                </li>
              ))}
            </ul>
          </div>
        )}

        {isQueued && elapsedSec >= 60 && (
          <p className="border-t border-[var(--color-border)] pt-3 text-xs text-[var(--color-text-secondary)]">
            Scan has been queued for over a minute. The runner may be busy with another job or still starting up.
          </p>
        )}

        {isInitializing && elapsedSec >= 120 && (
          <p className="border-t border-[var(--color-border)] pt-3 text-xs text-[var(--color-text-secondary)]">
            Still initializing after 2 minutes. Check scanner container or logs if this does not progress.
          </p>
        )}

        {onCancel && isActive && (
          <div className="flex justify-end border-t border-[var(--color-border)] pt-3">
            <Button
              variant="ghost"
              size="xs"
              onClick={onCancel}
              disabled={isCancelling}
              leadingIcon={<X className="h-3.5 w-3.5" strokeWidth={2.5} />}
              className="text-[var(--color-severity-critical-text)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical-text)]"
            >
              {isCancelling ? "Cancelling…" : "Cancel scan"}
            </Button>
          </div>
        )}
      </div>
    </Card>
  )
}
