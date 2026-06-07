"use client"

import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { buildOrgQuery } from "@/lib/shared/org-query"
import { formatScanTimestamp } from "@/lib/shared/utils"
import { fetchCurrentUser, type CurrentUser } from "@/lib/client/auth"
import { can } from "@/lib/shared/auth/roles.ts"
import { useSSE } from "@/components/providers/SSEProvider"
import type { ScanCompletedEvent, ScanFailedEvent } from "@/lib/shared/sse-types"

const RUNNING_STATUSES = new Set(["queued", "running", "ingesting"])

interface ScanRun {
  status: string
  finishedAt?: string | null
  startedAt?: string | null
  createdAt?: string
  error?: string | null
}

interface ModeOption {
  id: string
  label: string
  description: string
  disabled?: boolean
  disabledReason?: string
}

interface ToolRefreshControlsProps {
  org: string
  /** Display label for the org (shown as "Org: acme-org") */
  orgLabel?: string
  /** Tool event namespace (e.g. "dependencies", "code_scanning", "container_scanning") */
  eventKey: string
  /** Error label shown when start fails (e.g. "SCA scan") */
  toolLabel: string
  /** Fetch latest/lastCompleted run status */
  fetchRuns: (orgQuery: string) => Promise<{ payload: { latest?: ScanRun | null; lastCompleted?: ScanRun | null; error?: string | null } }>
  /** Start a scan run. scanMode is only passed when modeOptions are configured. */
  startRuns: (orgQuery: string, scanMode?: string) => Promise<{ ok: boolean; payload: { error?: string | null } }>
  /** Cancel a running scan */
  cancelRuns: (orgQuery: string) => Promise<unknown>
  /** Optional dropdown modes (e.g. SCA's Update SBOMs / Update Advisories) */
  modeOptions?: ModeOption[]
}

export function ToolRefreshControls({
  org,
  orgLabel,
  eventKey,
  toolLabel,
  fetchRuns,
  startRuns,
  cancelRuns,
  modeOptions,
}: ToolRefreshControlsProps) {
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [latestRun, setLatestRun] = useState<ScanRun | null>(null)
  const [lastCompletedRun, setLastCompletedRun] = useState<ScanRun | null>(null)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [isCancelling, setIsCancelling] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [showModeMenu, setShowModeMenu] = useState(false)
  const modeMenuRef = useRef<HTMLDivElement>(null)

  const orgQuery = useMemo(() => buildOrgQuery(org), [org])
  const isRunning = Boolean(latestRun && RUNNING_STATUSES.has(latestRun.status))
  const canRun = user ? can(user.role, "run_scans") : false

  useEffect(() => {
    void fetchCurrentUser().then(setUser)
  }, [])

  const loadRuns = useCallback(async () => {
    if (!orgQuery) return
    try {
      const { payload } = await fetchRuns(orgQuery)
      if (payload.error) {
        setError(payload.error)
        return
      }
      setError(null)
      setLatestRun(payload.latest ?? null)
      if (payload.lastCompleted !== undefined) {
        setLastCompletedRun(payload.lastCompleted ?? null)
      }
    } catch {
      // ignore
    }
  }, [orgQuery, fetchRuns])

  // Load once on mount
  useEffect(() => {
    void loadRuns()
  }, [loadRuns])

  // SSE: refresh on scan completion or failure (replaces polling)
  useSSE("scan.completed", (data: ScanCompletedEvent) => {
    if (data.tool !== eventKey) return
    void loadRuns()
  })

  useSSE("scan.failed", (data: ScanFailedEvent) => {
    if (data.tool !== eventKey) return
    void loadRuns()
  })

  useEffect(() => {
    if (!showModeMenu) return
    function handleClickOutside(e: MouseEvent) {
      if (modeMenuRef.current && !modeMenuRef.current.contains(e.target as Node)) {
        setShowModeMenu(false)
      }
    }
    document.addEventListener("mousedown", handleClickOutside)
    return () => document.removeEventListener("mousedown", handleClickOutside)
  }, [showModeMenu])

  async function handleRefresh(scanMode?: string) {
    setIsRefreshing(true)
    setShowModeMenu(false)
    setError(null)
    try {
      if (!isRunning && canRun) {
        const { ok, payload } = await startRuns(orgQuery, scanMode)
        if (!ok || payload.error) {
          setError(payload.error ?? `Failed to start ${toolLabel}`)
        }
      }
      await loadRuns()
      window.dispatchEvent(new Event(`${eventKey}:state-changed`))
    } catch {
      setError("Refresh failed")
    } finally {
      setIsRefreshing(false)
    }
  }

  async function handleCancel() {
    setIsCancelling(true)
    try {
      await cancelRuns(orgQuery)
      await loadRuns()
      window.dispatchEvent(new Event(`${eventKey}:state-changed`))
    } finally {
      setIsCancelling(false)
    }
  }

  const timestamp = lastCompletedRun?.finishedAt ? formatScanTimestamp(lastCompletedRun.finishedAt) : "Never"

  return (
    <div className="flex items-center gap-3">
      {error && <span className="text-xs text-[var(--color-severity-critical)] mr-2">{error}</span>}
      <div className="text-right text-xs space-y-0.5">
        <p className="text-[var(--color-text-secondary)]">
          {isRunning ? "Scanning..." : isRefreshing ? "Starting scan..." : `Last scanned: ${timestamp}`}
        </p>
        {orgLabel && <p className="text-[var(--color-text-tertiary)]">{orgLabel}</p>}
      </div>

      {isRunning && (
        <button
          type="button"
          onClick={() => void handleCancel()}
          disabled={isCancelling}
          className="inline-flex items-center gap-2 rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-2 text-sm font-medium text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-subtle)] disabled:opacity-50 transition-colors"
        >
          Cancel Scan
        </button>
      )}

      {canRun && !isRunning && (
        modeOptions && modeOptions.length > 0 ? (
          <div ref={modeMenuRef} className="relative inline-flex">
            <button
              type="button"
              onClick={() => void handleRefresh("full")}
              disabled={isRefreshing}
              className="rounded-l-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-medium text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)] disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
            >
              {isRefreshing ? "Starting..." : "Refresh"}
            </button>
            <button
              type="button"
              onClick={() => setShowModeMenu(!showModeMenu)}
              disabled={isRefreshing}
              className="rounded-r-lg border-l border-[var(--color-accent-hover)] bg-[var(--color-accent)] px-2 py-2 text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)] disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
            >
              &#9662;
            </button>
            {showModeMenu && (
              <div className="absolute right-0 top-full z-10 mt-1 w-56 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] shadow-lg">
                {modeOptions.map((mode, i) => (
                  <button
                    key={mode.id}
                    type="button"
                    onClick={() => !mode.disabled && void handleRefresh(mode.id)}
                    disabled={mode.disabled}
                    title={mode.disabled ? mode.disabledReason : undefined}
                    className={`w-full px-4 py-2.5 text-left text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] ${
                      mode.disabled ? "cursor-not-allowed opacity-40" : "hover:bg-[var(--color-surface-raised)]"
                    } ${i === 0 ? "rounded-t-lg" : ""} ${i === modeOptions.length - 1 ? "rounded-b-lg" : ""}`}
                  >
                    <span className="font-medium">{mode.label}</span>
                    <span className="block text-xs text-[var(--color-text-tertiary)]">
                      {mode.disabled && mode.disabledReason ? mode.disabledReason : mode.description}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
        ) : (
          <button
            type="button"
            onClick={() => void handleRefresh()}
            disabled={isRefreshing}
            className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-medium text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)] disabled:opacity-50"
          >
            {isRefreshing ? "Starting..." : "Refresh"}
          </button>
        )
      )}
    </div>
  )
}
