"use client"

import type { AuditEvent } from "@/lib/client/audit-api"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import { ActionBadge } from "./ActionBadge"
import { ActorBadge } from "./ActorBadge"

function relativeTime(iso: string | undefined): string {
  if (!iso) return "—"
  const diff = Date.now() - new Date(iso).getTime()
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function StatusPill({ code }: { code?: number }) {
  if (code == null) return <span className="text-[var(--color-text-tertiary)]">—</span>
  const ok = code < 400
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold tabular-nums ${
        ok
          ? "bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok-text)]"
          : "bg-[var(--color-severity-critical)]/10 text-[var(--color-severity-critical-text)]"
      }`}
    >
      {code}
    </span>
  )
}

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

const PER_PAGE = 25

interface AuditEventsTableProps {
  events: AuditEvent[]
  total: number
  loading?: boolean
  page: number
  onPageChange: (page: number) => void
  onRowClick: (event: AuditEvent) => void
}

export function AuditEventsTable({
  events,
  total,
  loading,
  page,
  onPageChange,
  onRowClick,
}: AuditEventsTableProps) {
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))

  return (
    <Card padding="none" elevation="sm" className="overflow-hidden rounded-md">
      <Table>
        <Thead>
          <Tr>
            {["Time", "Actor", "Action", "Resource", "Status", ""].map((h) => (
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
              <SkeletonRow />
              <SkeletonRow />
            </>
          ) : (
            events.map((ev) => (
              <Tr
                key={ev.id}
                tabIndex={0}
                role="button"
                interactive
                onClick={() => onRowClick(ev)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") onRowClick(ev) }}
                className="cursor-pointer focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-[var(--color-accent)]"
              >
                {/* Time */}
                <Td className="whitespace-nowrap text-xs text-[var(--color-text-tertiary)] tabular-nums">
                  {relativeTime(ev.occurred_at)}
                </Td>
                {/* Actor */}
                <Td className="max-w-[180px]">
                  <ActorBadge
                    actorId={ev.actor_id}
                    actorEmail={ev.actor_email}
                    actorRole={ev.actor_role}
                  />
                </Td>
                {/* Action */}
                <Td className="max-w-[240px]">
                  <ActionBadge action={ev.action} />
                </Td>
                {/* Resource */}
                <Td className="text-xs text-[var(--color-text-secondary)]">
                  <span className="block truncate max-w-[160px]" title={ev.resource_type}>
                    {ev.resource_type}
                  </span>
                  {ev.resource_id && (
                    <span className="block truncate max-w-[160px] font-[family-name:var(--font-jetbrains-mono)] text-2xs text-[var(--color-text-tertiary)]" title={ev.resource_id}>
                      {ev.resource_id}
                    </span>
                  )}
                </Td>
                {/* Status */}
                <Td>
                  <StatusPill code={ev.status_code} />
                </Td>
                {/* Detail arrow */}
                <Td className="text-right text-[var(--color-text-tertiary)]">
                  <svg className="inline h-4 w-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                    <path fillRule="evenodd" d="M7.21 14.77a.75.75 0 0 1 .02-1.06L11.168 10 7.23 6.29a.75.75 0 1 1 1.04-1.08l4.5 4.25a.75.75 0 0 1 0 1.08l-4.5 4.25a.75.75 0 0 1-1.06-.02Z" clipRule="evenodd" />
                  </svg>
                </Td>
              </Tr>
            ))
          )}
        </Tbody>
      </Table>

      {!loading && (
        <PaginatedTableFooter
          totalCount={total}
          page={page}
          perPage={PER_PAGE}
          totalPages={totalPages}
          onPageChange={onPageChange}
          onPerPageChange={() => {}}
          label="events"
        />
      )}
    </Card>
  )
}
