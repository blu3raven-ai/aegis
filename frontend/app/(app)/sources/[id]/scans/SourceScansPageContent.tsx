"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { History, X } from "lucide-react"
import { Button } from "@/components/ui/Button"
import { EmptyState } from "@/components/ui/EmptyState"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"
import { Skeleton } from "@/components/ui/Skeleton"
import { StatusPill, type Status } from "@/components/ui/StatusPill"
import { useSSE } from "@/components/providers/SSEProvider"
import { cancelScan } from "@/lib/client/scans-api"
import { getConnectionScanRuns, type ConnectionScanRun } from "@/lib/client/sources-api"
import { useHasPermission } from "@/lib/client/use-permission"
import { useSourceId } from "@/lib/client/use-source-id"
import { SCANNER_LABELS } from "@/lib/shared/sources-types"
import type { ScannerType } from "@/lib/shared/sources-types"
import { timeAgo } from "@/lib/shared/time-ago"

// A run is still in-flight (and therefore cancellable) until it reaches a
// terminal state.
const IN_FLIGHT = new Set(["queued", "running", "ingesting"])

// Scan runs accumulate ~3-4 per scan; page the history client-side so the
// table stays scannable. The fetch ceiling matches the resolver's own cap.
const PER_PAGE = 25
const FETCH_LIMIT = 200

// Map a scan-run status onto the StatusPill colour + a run-specific label.
// StatusPill's own labels ("Healthy"/"Failing") describe connections, so we
// pass through the right wording while reusing the coloured-dot primitive.
const STATUS_VIEW: Record<string, { tone: Status; label: string }> = {
  queued:    { tone: "warning", label: "Queued" },
  running:   { tone: "warning", label: "Running" },
  ingesting: { tone: "warning", label: "Ingesting" },
  completed: { tone: "healthy", label: "Completed" },
  completed_with_merge_error: { tone: "warning", label: "Completed (merge error)" },
  failed:    { tone: "failing", label: "Failed" },
  error:     { tone: "failing", label: "Failed" },
  cancelled: { tone: "stale",   label: "Cancelled" },
}

function scannerLabel(tool: string): string {
  if (tool in SCANNER_LABELS) return SCANNER_LABELS[tool as ScannerType]
  // iac_scanning, byo_import, pre_release, … — humanise the wire name.
  return tool.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
}

function formatDuration(ms: number | null): string {
  if (ms == null) return "—"
  const secs = Math.round(ms / 1000)
  if (secs < 60) return `${secs}s`
  const mins = Math.floor(secs / 60)
  const rem = secs % 60
  return rem ? `${mins}m ${rem}s` : `${mins}m`
}

export function SourceScansPageContent() {
  const connectionId = useSourceId()
  const { allowed: canCancel } = useHasPermission("manage_sources")
  const [runs, setRuns] = useState<ConnectionScanRun[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [page, setPage] = useState(1)

  const load = useCallback(async () => {
    if (!connectionId) return
    try {
      const data = await getConnectionScanRuns(connectionId, FETCH_LIMIT)
      setRuns(data)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load scan history")
      setRuns([])
    }
  }, [connectionId])

  useEffect(() => {
    void load()
  }, [load])

  // Keep the list live as runs finish or get cancelled elsewhere.
  useSSE("scan.completed", () => void load())
  useSSE("scan.failed", () => void load())
  useSSE("scan.cancelled", () => void load())

  async function handleCancel(scanId: string) {
    // Optimistically flip the row to cancelled so the UI responds instantly;
    // the button drops away with it. load() reconciles with server truth and
    // reverts the row if the cancel didn't actually take.
    setRuns((prev) =>
      prev?.map((r) => (r.scanId === scanId ? { ...r, status: "cancelled" } : r)) ?? prev,
    )
    try {
      await cancelScan(scanId)
    } finally {
      await load()
    }
  }

  const totalCount = runs?.length ?? 0
  const totalPages = Math.max(1, Math.ceil(totalCount / PER_PAGE))
  const safePage = Math.min(page, totalPages)
  const pageRuns = useMemo(
    () => (runs ?? []).slice((safePage - 1) * PER_PAGE, safePage * PER_PAGE),
    [runs, safePage],
  )

  if (runs === null) {
    return (
      <div className="px-6 py-6 space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    )
  }

  if (runs.length === 0) {
    return (
      <div className="px-6 py-6">
        <EmptyState
          icon={History}
          title={error ? "Couldn't load scan history" : "No scans yet"}
          description={
            error
              ? error
              : 'Each scan of this source will be recorded here with its status and results. Use "Scan Now" to run the first one.'
          }
        />
      </div>
    )
  }

  return (
    <div className="px-6 py-6">
      <div className="overflow-hidden rounded-md border border-[var(--color-border)]">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] text-left text-xs text-[var(--color-text-secondary)]">
              <th className="px-4 py-2.5 font-medium">Scanner</th>
              <th className="px-4 py-2.5 font-medium">Asset</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
              <th className="px-4 py-2.5 font-medium">Started</th>
              <th className="px-4 py-2.5 font-medium">Duration</th>
              <th className="px-4 py-2.5 text-right font-medium">Findings</th>
              <th className="px-4 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {pageRuns.map((run) => {
              const view = STATUS_VIEW[run.status] ?? { tone: "stale" as Status, label: run.status }
              const inFlight = IN_FLIGHT.has(run.status)
              return (
                <tr
                  key={run.scanId}
                  className="border-b border-[var(--color-border)] last:border-0 hover:bg-[var(--color-surface-raised)]"
                >
                  <td className="px-4 py-2.5 font-medium text-[var(--color-text-primary)]">
                    {scannerLabel(run.scannerType)}
                  </td>
                  <td className="max-w-[18rem] truncate px-4 py-2.5 text-[var(--color-text-secondary)]" title={run.assetName}>
                    {run.assetName || "—"}
                  </td>
                  <td className="px-4 py-2.5">
                    <StatusPill status={view.tone} label={view.label} />
                  </td>
                  <td className="px-4 py-2.5 text-[var(--color-text-secondary)] tabular-nums">
                    {run.startedAt ? timeAgo(run.startedAt) : "—"}
                  </td>
                  <td className="px-4 py-2.5 text-[var(--color-text-secondary)] tabular-nums">
                    {formatDuration(run.durationMs)}
                  </td>
                  <td className="px-4 py-2.5 text-right tabular-nums text-[var(--color-text-primary)]">
                    {run.findingsCount}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    {inFlight && canCancel && (
                      <Button
                        variant="ghost"
                        size="xs"
                        onClick={() => void handleCancel(run.scanId)}
                        leadingIcon={<X className="h-3.5 w-3.5" strokeWidth={2.5} />}
                      >
                        Cancel
                      </Button>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {totalPages > 1 && (
          <PaginatedTableFooter
            totalCount={totalCount}
            page={safePage}
            perPage={PER_PAGE}
            totalPages={totalPages}
            onPageChange={setPage}
            onPerPageChange={() => {}}
            label="scans"
          />
        )}
      </div>
    </div>
  )
}
