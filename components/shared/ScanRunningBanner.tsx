"use client"

import { useRef } from "react"

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
}

const ACTIVE_STATUSES = new Set(["queued", "running", "ingesting", "ai_review"])
const VISIBLE_STATUSES = new Set(["queued", "running", "ingesting", "ai_review", "failed"])

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
  ingesting: "Ingesting scanner output",
  classifying: "Classifying findings",
  ai_review: "Classifying findings",
}

type Tone = "running" | "queued" | "failed"

function toneClasses(tone: Tone): { dot: string; pulse: boolean; text: string } {
  if (tone === "failed") {
    return {
      dot: "bg-[var(--color-severity-critical)]",
      pulse: false,
      text: "text-[var(--color-severity-critical)]",
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
}: ScanRunningBannerProps) {
  const highestProgressRef = useRef<number>(0)

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

  const headline = isFailed
    ? `${scanLabel ?? "Scan"} failed for ${organization}`
    : isQueued
    ? `Waiting for runner to pick up ${scanLabel ?? "scan"} for ${organization}`
    : isInitializing
    ? "Preparing scanner"
    : `${scanLabel ?? "Scan"} in progress for ${currentRepo ?? organization}`

  const recentLogLines = (logTail ?? []).slice(-4)
  const progressFillWidth = isQueued ? 100 : Math.min(100, isActive ? Math.max(3, displayProgress) : displayProgress)

  return (
    <div
      role="status"
      aria-live="polite"
      className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]"
    >
      <div className="space-y-4 p-4 text-[13px] text-[var(--color-text-primary)]">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2">
            <span
              className={`inline-block h-2 w-2 rounded-full ${cfg.dot} ${cfg.pulse ? "motion-safe:animate-[scan-pulse_1.6s_ease-in-out_infinite]" : ""}`}
              aria-hidden="true"
            />
            <span className={`text-[12px] font-medium uppercase tracking-wide ${cfg.text}`}>
              {stageLabel}
            </span>
            <span className="truncate text-[var(--color-text-primary)]">{headline}</span>
          </div>
          <span className="text-[12px] tabular-nums text-[var(--color-text-secondary)]">
            {elapsed}
          </span>
        </div>

        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <span
              className="relative block h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--color-border)]"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round(displayProgress)}
              aria-label="Scan progress"
            >
              <span
                className={`absolute inset-y-0 left-0 rounded-full transition-[width] duration-700 ease-out ${
                  isFailed
                    ? "bg-[var(--color-severity-critical)]"
                    : isQueued
                    ? "bg-[var(--color-severity-medium)] motion-safe:animate-[scan-pulse_1.6s_ease-in-out_infinite]"
                    : "bg-[var(--color-accent)]"
                }`}
                style={{ width: `${progressFillWidth}%` }}
              />
            </span>
            <span className="w-10 text-right text-[12px] tabular-nums text-[var(--color-text-secondary)]">
              {Math.round(displayProgress)}%
            </span>
          </div>

          <div className="flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-[var(--color-text-secondary)]">
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
            ) : (
              <span>
                Repositories <span className="tabular-nums text-[var(--color-text-primary)]">{repoCountLabel}</span>
              </span>
            )}
            {showSyncLabel && <span>Sync: docker logs</span>}
            {currentRepo && !currentClassifying && (
              <span className="truncate" title={currentRepo}>
                Current <span className="font-mono text-[var(--color-text-primary)]">{currentRepo}</span>
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
            <p className="text-[12px] font-medium text-[var(--color-text-secondary)]">Activity</p>
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
          <p className="border-t border-[var(--color-border)] pt-3 text-[12px] text-[var(--color-text-secondary)]">
            Scan has been queued for over a minute. The runner may be busy with another job or still starting up.
          </p>
        )}

        {isInitializing && elapsedSec >= 120 && (
          <p className="border-t border-[var(--color-border)] pt-3 text-[12px] text-[var(--color-text-secondary)]">
            Still initializing after 2 minutes. Check scanner container or logs if this does not progress.
          </p>
        )}
      </div>
    </div>
  )
}
