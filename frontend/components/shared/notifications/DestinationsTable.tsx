"use client"

import type { NotificationDestination, TestSendResult } from "@/lib/client/destinations-api"
import { DestinationTypeIcon } from "./DestinationTypeIcon"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"

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
    <Tr>
      {[1, 2, 3, 4, 5, 6].map((i) => (
        <Td key={i}>
          <Skeleton className="h-4 w-full" />
        </Td>
      ))}
    </Tr>
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
        className="inline-flex items-center gap-1 text-xs text-[var(--color-status-ok-text)]"
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
      className="inline-flex max-w-[16rem] items-center gap-1 truncate text-xs text-[var(--color-severity-medium-text)]"
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
    <Card padding="none" className="overflow-hidden rounded-md">
      <Table>
        <Thead>
          <Tr>
            {["Name", "Type", "Status", "Filters", "Last updated", "Actions"].map((h) => (
              <Th key={h}>{h}</Th>
            ))}
          </Tr>
        </Thead>
        <Tbody>
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
                <Tr
                  key={dest.id}
                  interactive
                  onClick={() => onRowClick(dest)}
                  className="cursor-pointer"
                >
                  {/* Name */}
                  <Td className="font-medium text-[var(--color-text-primary)]">
                    {dest.name}
                  </Td>
                  {/* Type */}
                  <Td>
                    <span className="flex items-center gap-1.5">
                      <DestinationTypeIcon type={dest.destination_type} />
                      <span className="capitalize text-[var(--color-text-secondary)]">
                        {dest.destination_type}
                      </span>
                    </span>
                  </Td>
                  {/* Status */}
                  <Td>
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold ${
                        dest.enabled
                          ? "bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok-text)]"
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
                  </Td>
                  {/* Filters */}
                  <Td className="text-[var(--color-text-secondary)] text-xs">
                    {filterSummary(dest)}
                  </Td>
                  {/* Last updated */}
                  <Td className="text-[var(--color-text-tertiary)] text-xs">
                    {relativeTime(dest.updated_at)}
                  </Td>
                  {/* Actions */}
                  <Td onClick={(e) => e.stopPropagation()}>
                    <div className="flex flex-wrap items-center gap-2">
                      <Button
                        variant="ghost"
                        size="xs"
                        onClick={() => onEdit(dest)}
                        className="text-[var(--color-accent)] hover:bg-[var(--color-accent-subtle)] hover:text-[var(--color-accent)]"
                      >
                        Edit
                      </Button>
                      <Button
                        variant="ghost"
                        size="xs"
                        onClick={() => onTest(dest)}
                        disabled={sending}
                        aria-label={`Send test notification to ${dest.name}`}
                      >
                        {sending ? "Sending…" : "Test"}
                      </Button>
                      <Button
                        variant="ghost"
                        size="xs"
                        onClick={() => onDelete(dest)}
                        disabled={deletingId === dest.id}
                        className="text-[var(--color-severity-critical-text)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical-text)]"
                      >
                        {deletingId === dest.id ? "Deleting…" : "Delete"}
                      </Button>
                      <TestStatusInline status={testStatus} />
                    </div>
                  </Td>
                </Tr>
              )
            })
          )}
        </Tbody>
      </Table>
    </Card>
  )
}
