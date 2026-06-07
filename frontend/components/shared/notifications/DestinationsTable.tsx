"use client"

import type { NotificationDestination, TestSendResult } from "@/lib/client/destinations-api"
import { DestinationTypeIcon } from "./DestinationTypeIcon"

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function filterSummary(dest: NotificationDestination): string {
  const parts: string[] = []
  if (dest.event_filter?.min_severity) {
    parts.push(`≥ ${dest.event_filter.min_severity}`)
  }
  const types = dest.event_filter?.event_types
  if (types && types.length > 0) {
    parts.push(`${types.length} event${types.length === 1 ? "" : "s"}`)
  }
  return parts.length > 0 ? parts.join(", ") : "All events"
}

// Skeleton row for loading state
function SkeletonRow() {
  return (
    <tr>
      {[1, 2, 3, 4, 5, 6].map((i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 w-full animate-pulse rounded bg-[var(--color-surface-raised)]" />
        </td>
      ))}
    </tr>
  )
}

export type TestStatus =
  | { kind: "idle" }
  | { kind: "sending" }
  | { kind: "delivered"; latency_ms: number }
  | { kind: "failed"; error: string }

interface DestinationsTableProps {
  destinations: NotificationDestination[]
  loading?: boolean
  onRowClick: (dest: NotificationDestination) => void
  onEdit: (dest: NotificationDestination) => void
  onDelete: (dest: NotificationDestination) => void
  onTest: (dest: NotificationDestination) => void
  testStatuses: Record<number, TestStatus>
  deletingId?: number | null
}

function TestStatusInline({ status }: { status: TestStatus }) {
  if (status.kind === "idle") return null
  if (status.kind === "sending") {
    return (
      <span
        className="text-xs text-[var(--color-text-tertiary)]"
        role="status"
        aria-live="polite"
      >
        Sending…
      </span>
    )
  }
  if (status.kind === "delivered") {
    return (
      <span
        className="inline-flex items-center gap-1 text-xs text-[var(--color-status-ok)]"
        role="status"
        aria-live="polite"
      >
        <span aria-hidden="true">✓</span>
        Delivered in {status.latency_ms}ms
      </span>
    )
  }
  // failed
  return (
    <span
      className="inline-flex max-w-[16rem] items-center gap-1 truncate text-xs text-[var(--color-severity-medium)]"
      role="status"
      aria-live="polite"
      title={status.error}
    >
      <span aria-hidden="true">!</span>
      <span className="truncate">{status.error}</span>
    </span>
  )
}

export function DestinationsTable({
  destinations,
  loading,
  onRowClick,
  onEdit,
  onDelete,
  onTest,
  testStatuses,
  deletingId,
}: DestinationsTableProps) {
  return (
    <div className="overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)]">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[var(--color-border)]">
            {["Name", "Type", "Status", "Filters", "Last updated", "Actions"].map((h) => (
              <th
                key={h}
                className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--color-border-divider)]">
          {loading ? (
            <>
              <SkeletonRow />
              <SkeletonRow />
              <SkeletonRow />
            </>
          ) : (
            destinations.map((dest) => {
              const testStatus: TestStatus = testStatuses[dest.id] ?? { kind: "idle" }
              const sending = testStatus.kind === "sending"
              return (
                <tr
                  key={dest.id}
                  onClick={() => onRowClick(dest)}
                  className="cursor-pointer transition-colors hover:bg-[var(--color-bg-hover)]"
                >
                  {/* Name */}
                  <td className="px-4 py-3 font-medium text-[var(--color-text-primary)]">
                    {dest.name}
                  </td>
                  {/* Type */}
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1.5">
                      <DestinationTypeIcon type={dest.destination_type} />
                      <span className="capitalize text-[var(--color-text-secondary)]">
                        {dest.destination_type}
                      </span>
                    </span>
                  </td>
                  {/* Status */}
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold ${
                        dest.enabled
                          ? "bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok)]"
                          : "bg-[var(--color-border)] text-[var(--color-text-tertiary)]"
                      }`}
                    >
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${
                          dest.enabled ? "bg-[var(--color-status-ok)]" : "bg-[var(--color-text-tertiary)]"
                        }`}
                        aria-hidden="true"
                      />
                      {dest.enabled ? "Active" : "Disabled"}
                    </span>
                  </td>
                  {/* Filters */}
                  <td className="px-4 py-3 text-[var(--color-text-secondary)] text-xs">
                    {filterSummary(dest)}
                  </td>
                  {/* Last updated */}
                  <td className="px-4 py-3 text-[var(--color-text-tertiary)] text-xs">
                    {relativeTime(dest.updated_at)}
                  </td>
                  {/* Actions */}
                  <td
                    className="px-4 py-3"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={() => onEdit(dest)}
                        className="rounded px-2 py-1 text-xs font-medium text-[var(--color-accent)] hover:bg-[var(--color-accent)]/10 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--color-accent)]"
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => onTest(dest)}
                        disabled={sending}
                        aria-label={`Send test notification to ${dest.name}`}
                        className="rounded px-2 py-1 text-xs font-medium text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] disabled:cursor-not-allowed disabled:opacity-60 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--color-border-strong)]"
                      >
                        {sending ? "Sending…" : "Test"}
                      </button>
                      <button
                        type="button"
                        onClick={() => onDelete(dest)}
                        disabled={deletingId === dest.id}
                        className="rounded px-2 py-1 text-xs font-medium text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical)]/10 disabled:opacity-50 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--color-severity-critical)]"
                      >
                        {deletingId === dest.id ? "Deleting…" : "Delete"}
                      </button>
                      <TestStatusInline status={testStatus} />
                    </div>
                  </td>
                </tr>
              )
            })
          )}
        </tbody>
      </table>
    </div>
  )
}
