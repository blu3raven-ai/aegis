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
  queued: "Queued For Execution",
  scanning: "Scanning",
  ingesting: "Ingesting Scanner Output",
  classifying: "Classifying Findings",
  ai_review: "Classifying Findings",
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
  const terminalRepoLabel = expectedRepos
    ? `${String(finishedRepos).padStart(String(expectedRepos).length, "0")}/${expectedRepos}`
    : String(finishedRepos)

  const allStages = { ...DEFAULT_STAGES, ...extraStages }
  const stageLabel = isFailed
    ? "Scan Failed"
    : status === "queued"
    ? "Queued For Execution"
    : (allStages[progress?.stage ?? ""] ?? "Running")
  const recentLogLines = (logTail ?? []).slice(-4)

  return (
    <div className="overflow-hidden rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
      <div className="flex items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-4 font-mono">
        <div className="flex gap-2" aria-hidden="true">
          <span className="h-3 w-3 rounded-full bg-red-500" />
          <span className="h-3 w-3 rounded-full bg-yellow-400" />
          <span className="h-3 w-3 rounded-full bg-emerald-500" />
        </div>
        <p className="truncate text-sm text-[var(--color-text-primary)]">
          {commandLabel}
        </p>
      </div>

      <div className="space-y-4 p-5 font-mono text-xs text-[var(--color-text-primary)] sm:text-sm">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-[var(--color-text-primary)]">
            {isFailed ? (
              <><span className="text-red-500">[FAILED]</span> {scanLabel ?? "scan"} failed for {organization}</>
            ) : status === "queued" ? (
              <><span className="text-amber-400">[QUEUED]</span> waiting for runner to pick up {scanLabel ?? "scan"} for {organization}</>
            ) : (
              <><span className="text-[var(--color-accent)]">[RUNNING]</span>{" "}
              {isInitializing
                ? "preparing scanner"
                : `${scanLabel ?? "scan"} in progress for ${currentRepo ?? organization}`}</>
            )}
          </p>
          <p className="text-[var(--color-text-secondary)]">
            <span className="text-[var(--color-accent)]">elapsed</span> {elapsed}
          </p>
        </div>

        <div className="space-y-2 border-t border-[var(--color-border)] pt-3">
          <div className="flex flex-wrap gap-x-5 gap-y-1">
            <span>
              <span className="text-[var(--color-accent)]">stage: </span>
              {stageLabel.toLowerCase()}
            </span>
            {currentClassifying ? (
              <span>
                <span className="text-[var(--color-accent)]">findings classified: </span>
                {currentClassifying}
              </span>
            ) : progress?.stage === "ingesting" && progress?.expectedIngest ? (
              <span>
                <span className="text-[var(--color-accent)]">repositories ingested: </span>
                {String(progress.ingestedRepos ?? 0).padStart(String(progress.expectedIngest).length, "0")}/{progress.expectedIngest}
              </span>
            ) : (
              <span>
                <span className="text-[var(--color-accent)]">repositories scanned: </span>
                {terminalRepoLabel}
              </span>
            )}
            {showSyncLabel && (
              <span>
                <span className="text-[var(--color-accent)]">sync: </span>
                docker logs
              </span>
            )}
          </div>
          <div className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3">
            <span className="text-[var(--color-accent)]">progress</span>
            <span
              className="relative block h-3 min-w-0 overflow-hidden rounded-full bg-[var(--color-border)]"
              title={`${Math.round(displayProgress)}% complete`}
            >
              <span
                className={`absolute inset-y-0 left-0 rounded-full transition-all duration-700 ease-out ${
                  isFailed
                    ? "bg-gradient-to-r from-red-600 via-red-500 to-red-400"
                    : status === "queued"
                    ? "bg-amber-400/60 animate-pulse"
                    : "bg-gradient-to-r from-[var(--color-accent)] via-blue-400 to-blue-300"
                }`}
                style={{ width: status === "queued" ? "100%" : `${Math.min(100, isActive ? Math.max(3, displayProgress) : displayProgress)}%` }}
              />
            </span>
            <span className="text-right text-[var(--color-text-secondary)]">{Math.round(displayProgress)}%</span>
          </div>
          {currentClassifying ? (
            <p className="truncate text-[var(--color-text-secondary)]" title={`classifying ${currentClassifying}`}>
              <span className="text-[var(--color-accent)]">classifying=</span>
              {currentClassifying}
              <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-[var(--color-accent)]" aria-hidden="true" />
            </p>
          ) : currentRepo ? (
            <p className="truncate text-[var(--color-text-secondary)]" title={currentRepo}>
              <span className="text-[var(--color-accent)]">scanning=</span>
              {currentRepo}
              <span className="ml-1 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-[var(--color-accent)]" aria-hidden="true" />
            </p>
          ) : null}
        </div>

        {recentLogLines.length > 0 && (
          <div className="space-y-1 border-t border-[var(--color-border)] pt-3 text-xs">
            <p className="text-[var(--color-text-secondary)]">activity</p>
            {recentLogLines.map((line, index) => (
              <p key={`${index}-${line}`} className="truncate text-[var(--color-text-secondary)]" title={line}>
                <span className="text-[var(--color-accent)]">&gt;</span> {line}
              </p>
            ))}
          </div>
        )}

        {status === "queued" && elapsedSec >= 60 && (
          <p className="border-t border-[var(--color-border)] pt-3 text-[var(--color-text-secondary)]">
            Scan has been queued for over a minute. The runner may be busy with another job or still starting up.
          </p>
        )}

        {isInitializing && elapsedSec >= 120 && (
          <p className="border-t border-[var(--color-border)] pt-3 text-[var(--color-text-secondary)]">
            Still initializing after 2 minutes. Check scanner container/logs if this does not progress.
          </p>
        )}
      </div>
    </div>
  )
}
