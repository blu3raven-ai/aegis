"use client"

import { useCallback, useEffect, useState } from "react"
import { listAuditEvents, type AuditEvent, type AuditQueryFilters } from "@/lib/client/audit-api"
import { ApiClientError } from "@/lib/client/api-client.types"
import { AuditEventsTable } from "@/components/shared/audit/AuditEventsTable"
import { AuditEventDrawer } from "@/components/shared/audit/AuditEventDrawer"
import { AuditFilterBar, type AuditFilters, type DateWindow } from "@/components/shared/audit/AuditFilterBar"
import { EmptyAuditState } from "@/components/shared/audit/EmptyAuditState"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"

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
  const [errorStatus, setErrorStatus] = useState<number | null>(null)

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
  const knownResourceTypes = [...new Set(events.map((e) => e.resource_type).filter((v): v is string => !!v))].sort()

  const load = useCallback(async () => {
    setLoadState("loading")
    setErrorMessage(null)
    setErrorStatus(null)
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
      setTotal(res.total_count)
      setLoadState("ok")
    } catch (err: unknown) {
      if (err instanceof ApiClientError) {
        setErrorStatus(err.status)
        const detail = (err.body as { detail?: string } | null)?.detail
        setErrorMessage(detail ?? err.message)
      } else {
        setErrorMessage(err instanceof Error ? err.message : "Failed to load audit events")
      }
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
          <div className="rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface)] p-8">
            <p className="text-sm font-semibold text-[var(--color-severity-critical)]">
              Couldn&apos;t load audit events
            </p>
            <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
              {errorStatus === 409
                ? "The audit log is disabled. Set AEGIS_AUDIT_LOG_ENABLED=true to enable."
                : errorStatus === 403
                  ? "You don't have permission to view the audit log."
                  : (errorMessage ?? "An unknown error occurred.")}
            </p>
            <Button variant="secondary" size="md" onClick={load} className="mt-4">
              Retry
            </Button>
          </div>
        )}

        {/* Empty state */}
        {loadState === "ok" && events.length === 0 && (
          <Card padding="none">
            <EmptyAuditState filtered={isFiltered(filters)} />
          </Card>
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
