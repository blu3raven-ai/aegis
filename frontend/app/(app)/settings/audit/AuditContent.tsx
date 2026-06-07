"use client"

import { useCallback, useEffect, useState } from "react"
import { listAuditEvents, type AuditEvent, type AuditQueryFilters } from "@/lib/client/audit-api"
import { AuditEventsTable } from "@/components/shared/audit/AuditEventsTable"
import { AuditEventDrawer } from "@/components/shared/audit/AuditEventDrawer"
import { AuditFilterBar, type AuditFilters, type DateWindow } from "@/components/shared/audit/AuditFilterBar"
import { EmptyAuditState } from "@/components/shared/audit/EmptyAuditState"

const PER_PAGE = 25

function windowToIso(window: DateWindow): string | undefined {
  if (window === "all") return undefined
  const days = window === "7d" ? 7 : window === "30d" ? 30 : 90
  const d = new Date()
  d.setDate(d.getDate() - days)
  return d.toISOString()
}

function isFiltered(filters: AuditFilters): boolean {
  return !!(filters.action || filters.actorId || filters.resourceType)
}

type LoadState = "loading" | "ok" | "error"

export function AuditContent() {
  const [filters, setFilters] = useState<AuditFilters>({
    dateWindow: "7d",
    action: "",
    actorId: "",
    resourceType: "",
  })
  const [page, setPage] = useState(1)

  const [events, setEvents] = useState<AuditEvent[]>([])
  const [total, setTotal] = useState(0)
  const [loadState, setLoadState] = useState<LoadState>("loading")
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)

  // Derive unique facets from loaded events for filter dropdowns
  const knownActions = [...new Set(events.map((e) => e.action))].sort()
  const knownActors = [
    ...new Map(
      events
        .filter((e) => e.actor_id)
        .map((e) => [e.actor_id!, { id: e.actor_id!, email: e.actor_email }]),
    ).values(),
  ]
  const knownResourceTypes = [...new Set(events.map((e) => e.resource_type))].sort()

  const load = useCallback(async () => {
    setLoadState("loading")
    setErrorMessage(null)
    const query: AuditQueryFilters = {
      limit: PER_PAGE,
      offset: (page - 1) * PER_PAGE,
      since: windowToIso(filters.dateWindow),
      ...(filters.action ? { action: filters.action } : {}),
      ...(filters.actorId ? { actor_id: filters.actorId } : {}),
      ...(filters.resourceType ? { resource_type: filters.resourceType } : {}),
    }
    try {
      const res = await listAuditEvents(query)
      setEvents(res.events)
      setTotal(res.total)
      setLoadState("ok")
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to load audit events")
      setLoadState("error")
    }
  }, [filters, page])

  useEffect(() => { void load() }, [load])

  function handleFilterChange(next: Partial<AuditFilters>) {
    setFilters((prev) => ({ ...prev, ...next }))
    // Reset to page 1 whenever filters change
    setPage(1)
  }

  function openDrawer(event: AuditEvent) {
    setSelectedEvent(event)
    setDrawerOpen(true)
  }

  return (
    <>
      <div className="space-y-6">
        {/* Filter bar */}
        <AuditFilterBar
          filters={filters}
          onChange={handleFilterChange}
          knownActions={knownActions}
          knownActors={knownActors}
          knownResourceTypes={knownResourceTypes}
        />

        {/* Error state */}
        {loadState === "error" && (
          <div className="rounded-2xl border border-[var(--color-border-strong)] bg-[var(--color-surface)] p-8">
            <p className="text-sm font-semibold text-[var(--color-severity-critical)]">
              Couldn&apos;t load audit events
            </p>
            <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
              {errorMessage?.includes("403") || errorMessage?.includes("audit")
                ? "The audit log may be disabled. Set AEGIS_AUDIT_LOG_ENABLED=true to enable."
                : (errorMessage ?? "An unknown error occurred.")}
            </p>
            <button
              type="button"
              onClick={load}
              className="mt-4 rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)]"
            >
              Retry
            </button>
          </div>
        )}

        {/* Empty state */}
        {loadState === "ok" && events.length === 0 && (
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)]">
            <EmptyAuditState filtered={isFiltered(filters)} />
          </div>
        )}

        {/* Events table */}
        {(loadState === "loading" || (loadState === "ok" && events.length > 0)) && (
          <AuditEventsTable
            events={events}
            total={total}
            loading={loadState === "loading"}
            page={page}
            onPageChange={setPage}
            onRowClick={openDrawer}
          />
        )}
      </div>

      {/* Backdrop */}
      {drawerOpen && (
        <div
          className="fixed inset-0 z-30 bg-[var(--color-overlay)]"
          onClick={() => setDrawerOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Drawer */}
      <AuditEventDrawer
        event={selectedEvent}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      />
    </>
  )
}
