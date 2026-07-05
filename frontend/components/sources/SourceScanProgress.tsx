"use client"

import { useEffect, useRef, useState } from "react"
import { useSSE } from "@/components/providers/SSEProvider"
import { ScanRunningBanner } from "@/components/shared/ScanRunningBanner"
import { getActiveSourceScanRuns } from "@/lib/client/source-connections-api"
import { cn } from "@/lib/shared/utils"
import type { ScanCompletedEvent, ScanFailedEvent, ScanProgressEvent } from "@/lib/shared/sse-types"

interface RunProgress {
  percent?: number
  scannedRepos?: number
  finishedRepos?: number
  expectedRepos?: number | null
  currentRepo?: string | null
  stage?: string
}

interface ActiveRun {
  runId: string
  scannerType: string
  status: "queued" | "running" | "ingesting" | "failed" | "completed" | "cancelled"
  progress: RunProgress | null
  logTail: string[]
  startedAt: string | null
  createdAt: string
}

interface SourceScanProgressProps {
  connectionId: string
  org: string
  runIds: string[]
  onDone?: () => void
  onCancel?: () => void
  isCancelling?: boolean
}

const SCANNER_SHORT: Record<string, string> = {
  dependencies_scanning: "Dependency",
  secret_scanning: "Secret",
  code_scanning: "Code",
  container_scanning: "Container",
}

const TERMINAL_STATUSES = new Set(["completed", "failed", "cancelled"])

// Status priority for aggregation — higher wins.
const STATUS_PRIORITY: Record<string, number> = {
  failed: 4,
  ingesting: 3,
  running: 2,
  queued: 1,
}

function extractScannerType(runId: string): string {
  const parts = runId.split("-")
  return parts.length >= 3 ? parts.slice(2).join("-") : runId
}

function buildScanLabel(runs: ActiveRun[]): string {
  if (runs.length === 1) {
    const label = SCANNER_SHORT[runs[0].scannerType]
    return label ? `${label} scan` : "Scan"
  }
  const names = runs.map((r) => SCANNER_SHORT[r.scannerType] ?? r.scannerType)
  if (names.length <= 2) return `${names.join(" & ")} scan`
  return `${names.slice(0, -1).join(", ")} & ${names[names.length - 1]} scan`
}

export function SourceScanProgress({ connectionId, org, runIds, onDone, onCancel, isCancelling }: SourceScanProgressProps) {
  const now = Date.now()
  const [runs, setRuns] = useState<ActiveRun[]>(() =>
    runIds.map((runId) => ({
      runId,
      scannerType: extractScannerType(runId),
      status: "queued" as const,
      progress: null,
      logTail: [],
      startedAt: null,
      createdAt: new Date(now).toISOString(),
    })),
  )
  const [nowMs, setNowMs] = useState(now)
  const [shown, setShown] = useState(false)
  const onDoneRef = useRef(onDone)
  onDoneRef.current = onDone

  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  // Slide the floating banner in on mount.
  useEffect(() => {
    const raf = requestAnimationFrame(() => setShown(true))
    return () => cancelAnimationFrame(raf)
  }, [])

  // Reconcile against the backend on a poll so the banner self-corrects even
  // when a live SSE progress event was missed (e.g. queued → running), and so
  // it detects completion when a run drops out of the active set. The first
  // poll after a refresh also rehydrates the persisted progress/timing the
  // remount wiped, so the banner doesn't reset to a blank "preparing" state.
  useEffect(() => {
    if (!connectionId) return
    let cancelled = false

    async function poll() {
      const result = await getActiveSourceScanRuns(connectionId)
      if (cancelled || !result.ok) return
      const byRun = new Map(result.data.runs.map((r) => [r.runId, r]))
      setRuns((prev) =>
        prev.map((run) => {
          if (TERMINAL_STATUSES.has(run.status)) return run
          const snap = byRun.get(run.runId)
          // Dropped from the active set → it finished.
          if (!snap) return { ...run, status: "completed" as const }

          let next = run
          // Rehydrate state lost on a refresh remount. Only fill what we don't
          // already have, so the poll never clobbers fresher live SSE data.
          if (!run.startedAt && snap.startedAt) {
            next = { ...next, startedAt: snap.startedAt, createdAt: snap.createdAt ?? next.createdAt }
          }
          if (!run.progress && snap.progress) {
            next = {
              ...next,
              progress: snap.progress,
              logTail: snap.logTail.length ? snap.logTail : next.logTail,
            }
          }
          // Status: never move backwards (SSE may already show a later stage).
          if ((STATUS_PRIORITY[snap.status] ?? 0) > (STATUS_PRIORITY[next.status] ?? 0)) {
            next = { ...next, status: snap.status as ActiveRun["status"] }
          }
          return next
        }),
      )
    }

    void poll()
    const id = setInterval(() => void poll(), 4000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [connectionId])

  useEffect(() => {
    if (runs.length > 0 && runs.every((r) => TERMINAL_STATUSES.has(r.status))) {
      onDoneRef.current?.()
    }
  }, [runs])

  useSSE("scan.progress", (data: ScanProgressEvent) => {
    setRuns((prev) =>
      prev.map((r) =>
        r.runId !== data.runId
          ? r
          : {
              ...r,
              status: "running" as const,
              progress: data.progress,
              logTail: data.logTail ?? [],
              startedAt: r.startedAt ?? new Date().toISOString(),
            },
      ),
    )
  })

  useSSE("scan.completed", (data: ScanCompletedEvent) => {
    setRuns((prev) =>
      prev.map((r) => (r.runId !== data.runId ? r : { ...r, status: "completed" as const })),
    )
  })

  useSSE("scan.failed", (data: ScanFailedEvent) => {
    setRuns((prev) =>
      prev.map((r) => (r.runId !== data.runId ? r : { ...r, status: "failed" as const })),
    )
  })

  const visibleRuns = runs.filter((r) => !TERMINAL_STATUSES.has(r.status) || r.status === "failed")

  if (visibleRuns.length === 0) return null

  // Aggregate to a single banner.
  const aggRun = visibleRuns.reduce((best, r) =>
    (STATUS_PRIORITY[r.status] ?? 0) > (STATUS_PRIORITY[best.status] ?? 0) ? r : best,
  )
  const avgPercent =
    visibleRuns.reduce((sum, r) => sum + (r.progress?.percent ?? 0), 0) / visibleRuns.length
  const latestLogTail =
    visibleRuns.find((r) => r.logTail.length > 0)?.logTail ?? []
  const startedAt =
    visibleRuns.map((r) => r.startedAt).filter(Boolean).sort()[0] ?? null
  const createdAt =
    visibleRuns.map((r) => r.createdAt).sort()[0] ?? new Date().toISOString()
  const aggProgress: RunProgress = {
    ...aggRun.progress,
    percent: Math.round(avgPercent),
  }
  const scanLabel = buildScanLabel(visibleRuns)

  // Per-scanner status counts so the banner can show how many are queued vs
  // running vs done across the whole scan.
  const runCounts = {
    total: runs.length,
    queued: runs.filter((r) => r.status === "queued").length,
    running: runs.filter((r) => r.status === "running" || r.status === "ingesting").length,
    completed: runs.filter((r) => r.status === "completed").length,
    failed: runs.filter((r) => r.status === "failed").length,
  }

  // Positioning + stacking is owned by ScanProgressProvider's fixed container;
  // this renders a single slide-in banner card.
  return (
    <div
      className={cn(
        "pointer-events-auto w-[min(26rem,calc(100vw-2rem))] transition-all duration-300 ease-out motion-reduce:transition-none",
        shown ? "translate-y-0 opacity-100" : "translate-y-4 opacity-0",
      )}
    >
      <ScanRunningBanner
        organization={org}
        status={aggRun.status}
        progress={aggProgress}
        logTail={latestLogTail}
        startedAt={startedAt}
        createdAt={createdAt}
        nowMs={nowMs}
        commandLabel=""
        scanLabel={scanLabel}
        runCounts={runCounts}
        activeScannerLabel={SCANNER_SHORT[aggRun.scannerType]}
        onCancel={onCancel}
        isCancelling={isCancelling}
      />
    </div>
  )
}
