"use client"

import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { PageHeader } from "@/components/layout/PageHeader"
import { SecretsDashboardView } from "@/app/(app)/secrets/_components/SecretsDashboardView"
import { useSSE } from "@/components/providers/SSEProvider"
import type { ScanProgressEvent, ScanCompletedEvent, ScanFailedEvent } from "@/lib/shared/sse-types"
import {
  cancelSecretsRuns,
  fetchSecretsRuns,
  startSecretsRuns,
} from "@/lib/client/secrets/dashboard-client"
import { formatScanTimestamp } from "@/lib/shared/utils"
import { buildOrgQuery } from "@/lib/shared/org-query"
import { fetchCurrentUser, type CurrentUser } from "@/lib/client/auth"
import { can } from "@/lib/shared/auth/roles.ts"
import type { SecretScanRun } from "@/lib/shared/secrets/types"

interface Props {
  orgs: string[]
  initialTab?: string
  canEdit?: boolean
  prerequisitesMet?: boolean
}

const RUNNING_STATUSES = new Set<SecretScanRun["status"]>(["queued", "running", "ingesting"])

function SecretIcon() {
  return (
    <div className="p-1.5 bg-[var(--color-accent-subtle)] rounded-lg">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        className="w-5 h-5 text-[var(--color-accent)]"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={1.8}
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z"
        />
      </svg>
    </div>
  )
}

export function SecretsPageShell({ orgs, initialTab, canEdit, prerequisitesMet }: Props) {
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [latestRun, setLatestRun] = useState<SecretScanRun | null>(null)
  const [lastCompletedRun, setLastCompletedRun] = useState<SecretScanRun | null>(null)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [isCancelling, setIsCancelling] = useState(false)
  const [showDepthMenu, setShowDepthMenu] = useState(false)
  const [refreshKey, setRefreshKey] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const consecutiveFailures = useRef(0)

  const depthMenuRef = useRef<HTMLDivElement>(null)

  const orgQuery = useMemo(() => buildOrgQuery(orgs), [orgs])
  const orgLabel = orgs.join(", ")

  const isRunning = Boolean(latestRun && RUNNING_STATUSES.has(latestRun.status))
  const canRun = user ? can(user.role, "run_scans") : false

  const loadLatestRuns = useCallback(async () => {
    if (!orgQuery) return
    try {
      const { payload } = await fetchSecretsRuns(orgQuery)
      if (payload.error) {
        consecutiveFailures.current += 1
        if (consecutiveFailures.current >= 2) setError(payload.error)
        return
      }
      consecutiveFailures.current = 0
      setError(null)
      setLatestRun(payload.latest ?? null)
      if (payload.lastCompleted !== undefined) {
        setLastCompletedRun(payload.lastCompleted ?? null)
      }
    } catch (err) {
      consecutiveFailures.current += 1
      if (consecutiveFailures.current >= 2) {
        setError(err instanceof Error ? err.message : "Failed to fetch scan runs")
      }
    }
  }, [orgQuery])

  useEffect(() => {
    void fetchCurrentUser().then(setUser)
  }, [])

  useEffect(() => {
    void loadLatestRuns()
  }, [loadLatestRuns])

  // ── SSE: real-time scan updates ──────────────────────────────────────────
  useSSE("scan.progress", (data: ScanProgressEvent) => {
    if (data.tool !== "secrets") return
    if ((data as any)._refresh) { void loadLatestRuns(); return }
    setLatestRun((prev) => {
      if (!prev || prev.id !== data.runId) { void loadLatestRuns(); return prev }
      if (prev.status === "completed" || prev.status === "failed" || prev.status === "cancelled") return prev
      return { ...prev, status: "running" as const, progress: { ...prev.progress, ...data.progress, stage: data.progress.stage as typeof prev.progress.stage }, logTail: data.logTail }
    })
  })

  useSSE("scan.completed", (data: ScanCompletedEvent) => {
    if (data.tool !== "secrets") return
    void loadLatestRuns()
  })

  useSSE("scan.failed", (data: ScanFailedEvent) => {
    if (data.tool !== "secrets") return
    void loadLatestRuns()
  })

  useEffect(() => {
    function handleUpdated() {
      void loadLatestRuns()
    }
    window.addEventListener("dashboard:data-updated", handleUpdated)
    return () => window.removeEventListener("dashboard:data-updated", handleUpdated)
  }, [loadLatestRuns])

  useEffect(() => {
    if (!showDepthMenu) return
    function handleClickOutside(e: MouseEvent) {
      if (depthMenuRef.current && !depthMenuRef.current.contains(e.target as Node)) {
        setShowDepthMenu(false)
      }
    }
    document.addEventListener("mousedown", handleClickOutside)
    return () => document.removeEventListener("mousedown", handleClickOutside)
  }, [showDepthMenu])

  async function handleRefresh(overrideDepth?: "light" | "deep" | "ai_enhanced") {
    setIsRefreshing(true)
    setError(null)
    setShowDepthMenu(false)

    try {
      if (!isRunning && canRun) {
        const mode = lastCompletedRun ? "incremental" : "full"
        const { ok, payload } = await startSecretsRuns(orgQuery, mode, overrideDepth)
        if (!ok || payload.error) {
          setError(payload.error ?? "Failed to start secret scan")
        }
      }

      setRefreshKey((k) => k + 1)
      await loadLatestRuns()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Refresh failed")
    } finally {
      setIsRefreshing(false)
    }
  }

  async function handleCancelScan() {
    setIsCancelling(true)
    setError(null)
    try {
      const { ok, payload } = await cancelSecretsRuns(orgQuery)
      if (!ok || payload.error) {
        setError(payload.error ?? "Failed to cancel secret scan")
        return
      }
      void loadLatestRuns()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to cancel secret scan")
    } finally {
      setIsCancelling(false)
    }
  }

  const timestamp = lastCompletedRun?.finishedAt ? formatScanTimestamp(lastCompletedRun.finishedAt) : "Never"

  const hasOrgs = orgs.length > 0

  const controls = (
    <div className="flex items-center gap-3">
      {error && <span className="text-xs text-[var(--color-severity-critical)] mr-2">{error}</span>}
      <div className="text-right text-xs space-y-0.5">
        <p className="text-[var(--color-text-secondary)]">
          {isRunning ? "Scanning..." : isRefreshing ? "Starting scan..." : `Last scanned: ${timestamp}`}
        </p>
        <p className="text-[var(--color-text-tertiary)]">{hasOrgs ? orgLabel : "No organisations configured"}</p>
      </div>

      {isRunning && (
        <button
          type="button"
          onClick={handleCancelScan}
          disabled={isCancelling}
          className="inline-flex items-center gap-2 rounded-lg border border-[var(--color-severity-critical)]/20 bg-[var(--color-severity-critical)]/10 px-3 py-2 text-sm font-medium text-[var(--color-severity-critical)] transition-colors hover:bg-[var(--color-severity-critical)]/15 disabled:opacity-50"
        >
          Cancel Scan
        </button>
      )}

      {canRun && !isRunning && (
        <div ref={depthMenuRef} className="relative inline-flex">
          <button
            onClick={() => handleRefresh()}
            disabled={isRefreshing}
            className="rounded-l-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-medium text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)] disabled:opacity-50"
          >
            {isRefreshing ? "Starting..." : "Refresh"}
          </button>
          <button
            onClick={() => setShowDepthMenu(!showDepthMenu)}
            disabled={isRefreshing}
            className="rounded-r-lg border-l border-[var(--color-accent-hover)] bg-[var(--color-accent)] px-2 py-2 text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)] disabled:opacity-50"
          >
            ▾
          </button>
          {showDepthMenu && (
            <div className="absolute right-0 top-full z-10 mt-1 w-52 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] shadow-lg">
              <button
                onClick={() => handleRefresh("light")}
                className="w-full px-4 py-2.5 text-left text-sm hover:bg-[var(--color-surface-raised)] rounded-t-lg"
              >
                <span className="font-medium">Light Scan</span>
                <span className="block text-xs text-[var(--color-text-tertiary)]">Current code only (minutes)</span>
              </button>
              <button
                onClick={() => handleRefresh("deep")}
                className="w-full px-4 py-2.5 text-left text-sm hover:bg-[var(--color-surface-raised)]"
              >
                <span className="font-medium">Deep Scan</span>
                <span className="block text-xs text-[var(--color-text-tertiary)]">Full git history (hours)</span>
              </button>
              <button
                onClick={() => handleRefresh("ai_enhanced")}
                className="w-full px-4 py-2.5 text-left text-sm hover:bg-[var(--color-surface-raised)] rounded-b-lg"
              >
                <span className="font-medium">AI Enhanced Scan</span>
                <span className="block text-xs text-[var(--color-text-tertiary)]">AI classifier, full history (hours)</span>
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )

  return (
    <>
      <PageHeader
        icon={<SecretIcon />}
        title="Secret Scanning"
        description="Detects exposed credentials, API keys, and tokens across your repositories"
        controls={controls}
      />
      {hasOrgs ? (
        <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-8">
          <SecretsDashboardView
            key={refreshKey}
            orgs={orgs}
            latestRun={latestRun}
            onLatestRunUpdate={setLatestRun}
            initialTab={initialTab}
            canEdit={canEdit}
            prerequisitesMet={prerequisitesMet}
          />
        </main>
      ) : (
        <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-8">
          <SecretsDashboardView
            key={refreshKey}
            orgs={orgs}
            latestRun={latestRun}
            onLatestRunUpdate={setLatestRun}
            initialTab={initialTab}
            canEdit={canEdit}
            prerequisitesMet={prerequisitesMet}
          />
        </main>
      )}
    </>
  )
}
