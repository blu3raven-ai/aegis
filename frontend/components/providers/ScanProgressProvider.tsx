"use client"

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react"
import { ChevronDown, X } from "lucide-react"
import { Button } from "@/components/ui/Button"
import { SourceScanProgress } from "@/components/sources/SourceScanProgress"
import {
  cancelSourceScan,
  getActiveSourceScanRuns,
  getAllActiveSourceScans,
} from "@/lib/client/source-connections-api"
import { useHasPermission } from "@/lib/client/use-permission"
import { cn } from "@/lib/shared/utils"

// Full cards shown before the rest collapse behind a "+N more" toggle, so a
// burst of concurrent scans can't grow the stack off the top of the viewport.
const VISIBLE_LIMIT = 2

// Active scans are persisted here so the banner survives a full page reload
// (in-memory React state is wiped on refresh); on load each entry is verified
// against the backend before it's shown again.
const STORAGE_KEY = "aegis:active-scans"

interface ActiveScan {
  connectionId: string
  /** Display label (org/owner or source name) for the banner. */
  org: string
  runIds: string[]
}

interface ScanProgressValue {
  isScanning: (connectionId: string) => boolean
  isCancelling: (connectionId: string) => boolean
  /** Register (or replace) an active scan so its banner shows app-wide. */
  register: (scan: ActiveScan) => void
  unregister: (connectionId: string) => void
  cancel: (connectionId: string) => Promise<void>
  /** Hide the banner without stopping the scan; stays hidden until this
   *  connection's current run finishes, so a later scan shows again. */
  dismiss: (connectionId: string) => void
}

const ScanProgressContext = createContext<ScanProgressValue | null>(null)

export function useScanProgress(): ScanProgressValue {
  const ctx = useContext(ScanProgressContext)
  if (!ctx) {
    throw new Error("useScanProgress must be used within ScanProgressProvider")
  }
  return ctx
}

/**
 * Holds in-flight source scans above the page layouts so their progress banner
 * persists across client-side navigation — the user can leave the source page
 * and still watch (and cancel) the scan from anywhere in the app.
 */
export function ScanProgressProvider({ children }: { children: React.ReactNode }) {
  const [scans, setScans] = useState<ActiveScan[]>([])
  const [cancelling, setCancelling] = useState<Record<string, boolean>>({})
  const [expanded, setExpanded] = useState(false)
  // Cancelling a source scan requires manage_sources (the permission the
  // /scan/cancel endpoint enforces); hide the controls otherwise so we never
  // show an action that would 403.
  const { allowed: canCancel } = useHasPermission("manage_sources")
  // Mirror of `scans` so cancel() reads the latest run IDs without re-creating.
  const scansRef = useRef<ActiveScan[]>([])
  scansRef.current = scans
  // Connections the user manually dismissed. The discovery poll skips these so
  // a dismissed banner can't pop back; an entry clears once the connection has
  // no active runs, so the next scan is free to show a fresh banner.
  const dismissedRef = useRef<Set<string>>(new Set())

  const register = useCallback((scan: ActiveScan) => {
    setScans((prev) => [...prev.filter((s) => s.connectionId !== scan.connectionId), scan])
  }, [])

  const dismiss = useCallback((connectionId: string) => {
    dismissedRef.current.add(connectionId)
    setScans((prev) => prev.filter((s) => s.connectionId !== connectionId))
  }, [])

  const unregister = useCallback((connectionId: string) => {
    setScans((prev) => prev.filter((s) => s.connectionId !== connectionId))
    setCancelling((prev) => {
      if (!(connectionId in prev)) return prev
      const next = { ...prev }
      delete next[connectionId]
      return next
    })
  }, [])

  const cancel = useCallback(
    async (connectionId: string) => {
      const scan = scansRef.current.find((s) => s.connectionId === connectionId)
      if (!scan || cancelling[connectionId]) return
      setCancelling((prev) => ({ ...prev, [connectionId]: true }))
      try {
        await cancelSourceScan(connectionId, scan.runIds)
        unregister(connectionId)
      } finally {
        setCancelling((prev) => ({ ...prev, [connectionId]: false }))
      }
    },
    [cancelling, unregister],
  )

  // Gates persistence until the initial restore has read storage. Without this,
  // the empty mount-time state would wipe the persisted entry (via the effect
  // below, which runs first) before restore could read it back.
  const hydratedRef = useRef(false)

  // Persist the active set so a refresh can restore it.
  useEffect(() => {
    if (!hydratedRef.current) return
    try {
      if (scans.length) localStorage.setItem(STORAGE_KEY, JSON.stringify(scans))
      else localStorage.removeItem(STORAGE_KEY)
    } catch {
      /* storage unavailable — banner just won't survive refresh */
    }
  }, [scans])

  // On load, restore persisted scans but only after confirming each is still
  // in-flight with the backend (so we never show a stale, already-finished one).
  useEffect(() => {
    let persisted: ActiveScan[] = []
    try {
      persisted = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "[]")
    } catch {
      persisted = []
    }
    if (!Array.isArray(persisted) || persisted.length === 0) {
      hydratedRef.current = true
      return
    }

    let cancelled = false
    void Promise.all(
      persisted.map(async (s) => {
        if (!s?.connectionId) return null
        const r = await getActiveSourceScanRuns(s.connectionId)
        return r.ok && r.data.runIds.length > 0
          ? { connectionId: s.connectionId, org: s.org, runIds: r.data.runIds }
          : null
      }),
    ).then((results) => {
      if (cancelled) return
      for (const scan of results) {
        if (scan) register(scan)
      }
      hydratedRef.current = true
    })
    return () => {
      cancelled = true
    }
  }, [register])

  // Discover active scans app-wide (manual or scheduled) so the banner appears
  // for runs the user didn't start from this page — e.g. a scheduled scan that
  // kicked off in the background. Polls on mount and periodically; SourceScan-
  // Progress handles per-run progress and unregisters each on completion.
  useEffect(() => {
    let cancelled = false

    async function discover() {
      const result = await getAllActiveSourceScans()
      if (cancelled || !result.ok) return
      // A dismissal only holds while that connection is still scanning; once it
      // drops out of the active set, clear it so its next scan can show.
      const activeIds = new Set(result.data.scans.map((s) => s.connectionId))
      for (const id of [...dismissedRef.current]) {
        if (!activeIds.has(id)) dismissedRef.current.delete(id)
      }
      for (const scan of result.data.scans) {
        if (scan.runIds.length === 0) continue
        // Honour a manual dismissal — don't re-summon a banner the user closed.
        if (dismissedRef.current.has(scan.connectionId)) continue
        // Skip re-registering an unchanged scan so the 10s poll doesn't churn
        // state for banners that are already showing.
        const existing = scansRef.current.find((s) => s.connectionId === scan.connectionId)
        const unchanged =
          existing &&
          existing.runIds.length === scan.runIds.length &&
          existing.runIds.every((r) => scan.runIds.includes(r))
        if (!unchanged) register(scan)
      }
    }

    void discover()
    const id = setInterval(() => void discover(), 10000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [register])

  const isScanning = useCallback(
    (connectionId: string) => scans.some((s) => s.connectionId === connectionId),
    [scans],
  )
  const isCancelling = useCallback(
    (connectionId: string) => Boolean(cancelling[connectionId]),
    [cancelling],
  )

  const value = useMemo<ScanProgressValue>(
    () => ({ isScanning, isCancelling, register, unregister, cancel, dismiss }),
    [isScanning, isCancelling, register, unregister, cancel, dismiss],
  )

  const hasOverflow = scans.length > VISIBLE_LIMIT
  const visibleScans = expanded ? scans : scans.slice(0, VISIBLE_LIMIT)
  const hiddenCount = scans.length - VISIBLE_LIMIT
  const showCancelAll = canCancel && scans.length > 1
  const showFooter = hasOverflow || showCancelAll

  return (
    <ScanProgressContext.Provider value={value}>
      {children}
      {/* Global floating banner stack — bottom-right, above page content. */}
      <div className="pointer-events-none fixed inset-x-0 bottom-0 z-50 flex flex-col items-end gap-3 p-4 sm:p-6">
        <div
          className={cn(
            "flex flex-col items-end gap-3",
            // When expanded the stack can exceed the viewport, so cap it and
            // let the cards scroll while the footer below stays pinned.
            expanded && hasOverflow && "pointer-events-auto max-h-[70vh] overflow-y-auto py-1 pr-1",
          )}
        >
          {visibleScans.map((scan) => (
            <SourceScanProgress
              key={scan.connectionId}
              connectionId={scan.connectionId}
              org={scan.org}
              runIds={scan.runIds}
              onDone={() => unregister(scan.connectionId)}
              onDismiss={() => dismiss(scan.connectionId)}
              onCancel={canCancel ? () => void cancel(scan.connectionId) : undefined}
              isCancelling={isCancelling(scan.connectionId)}
            />
          ))}
        </div>
        {showFooter && (
          <div className="pointer-events-auto flex w-[min(26rem,calc(100vw-2rem))] items-center justify-between gap-2 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 shadow-[var(--shadow-nav)] ring-1 ring-black/5">
            {showCancelAll ? (
              <Button
                variant="ghost"
                size="xs"
                onClick={() => scans.forEach((s) => void cancel(s.connectionId))}
                leadingIcon={<X className="h-3.5 w-3.5" strokeWidth={2.5} />}
                className="text-[var(--color-severity-critical-text)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical-text)]"
              >
                Cancel all
              </Button>
            ) : (
              <span aria-hidden="true" />
            )}
            {hasOverflow ? (
              <button
                type="button"
                onClick={() => setExpanded((v) => !v)}
                aria-expanded={expanded}
                className="flex items-center gap-1 px-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
              >
                {expanded ? "Show fewer" : `+${hiddenCount} more scanning`}
                <ChevronDown
                  className={cn("h-3.5 w-3.5 transition-transform motion-reduce:transition-none", expanded && "rotate-180")}
                  aria-hidden="true"
                />
              </button>
            ) : (
              <span aria-hidden="true" />
            )}
          </div>
        )}
      </div>
    </ScanProgressContext.Provider>
  )
}
