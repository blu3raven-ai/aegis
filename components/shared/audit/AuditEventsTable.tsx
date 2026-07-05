"use client"

import type { AuditEvent } from "@/lib/client/audit-api"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"
import { ActionBadge } from "./ActionBadge"
import { ActorBadge } from "./ActorBadge"

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

function StatusPill({ code }: { code?: number }) {
  if (code == null) return <span className="text-[var(--color-text-tertiary)]">—</span>
  const ok = code < 400
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold tabular-nums ${
        ok
          ? "bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok)]"
          : "bg-[var(--color-severity-critical)]/10 text-[var(--color-severity-critical)]"
      }`}
    >
      {code}
    </span>
  )
}

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
    <div className="overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-card)]">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[var(--color-border)]">
            {["Time", "Actor", "Action", "Resource", "Status", ""].map((h) => (
              <th
                key={h}
                className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)]"
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
              <SkeletonRow />
              <SkeletonRow />
            </>
          ) : (
            events.map((ev) => (
              <tr
                key={ev.id}
                tabIndex={0}
                role="button"
                onClick={() => onRowClick(ev)}
                onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") onRowClick(ev) }}
                className="cursor-pointer transition-colors hover:bg-[var(--color-bg-hover)] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-[var(--color-accent)]"
              >
                {/* Time */}
                <td className="px-4 py-3 whitespace-nowrap text-xs text-[var(--color-text-tertiary)] tabular-nums">
                  {relativeTime(ev.occurred_at)}
                </td>
                {/* Actor */}
                <td className="px-4 py-3 max-w-[180px]">
                  <ActorBadge
                    actorId={ev.actor_id}
                    actorEmail={ev.actor_email}
                    actorRole={ev.actor_role}
                  />
                </td>
                {/* Action */}
                <td className="px-4 py-3 max-w-[240px]">
                  <ActionBadge action={ev.action} />
                </td>
                {/* Resource */}
                <td className="px-4 py-3 text-xs text-[var(--color-text-secondary)]">
                  <span className="block truncate max-w-[160px]" title={ev.resource_type}>
                    {ev.resource_type}
                  </span>
                  {ev.resource_id && (
                    <span className="block truncate max-w-[160px] font-[family-name:var(--font-jetbrains-mono)] text-2xs text-[var(--color-text-tertiary)]" title={ev.resource_id}>
                      {ev.resource_id}
                    </span>
                  )}
                </td>
                {/* Status */}
                <td className="px-4 py-3">
                  <StatusPill code={ev.status_code} />
                </td>
                {/* Detail arrow */}
                <td className="px-4 py-3 text-right text-[var(--color-text-tertiary)]">
                  <svg className="inline h-4 w-4" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                    <path fillRule="evenodd" d="M7.21 14.77a.75.75 0 0 1 .02-1.06L11.168 10 7.23 6.29a.75.75 0 1 1 1.04-1.08l4.5 4.25a.75.75 0 0 1 0 1.08l-4.5 4.25a.75.75 0 0 1-1.06-.02Z" clipRule="evenodd" />
                  </svg>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>

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
    </div>
  )
}
