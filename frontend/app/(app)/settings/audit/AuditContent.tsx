"use client"

import { useCallback, useEffect, useState } from "react"
import {
  listAuditEvents,
  listAuditFacets,
  type AuditEvent,
  type AuditQueryFilters,
} from "@/lib/client/audit-api"
import { ApiClientError } from "@/lib/client/api-client.types"
import { AuditEventsTable } from "@/components/shared/audit/AuditEventsTable"
import { AuditEventDrawer } from "@/components/shared/audit/AuditEventDrawer"
import { AuditCommandBar, type AuditFilters, type DateWindow } from "@/components/shared/audit/AuditCommandBar"
import { EmptyAuditState } from "@/components/shared/audit/EmptyAuditState"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"

const PER_PAGE = 25
const SEARCH_DEBOUNCE_MS = 300

function windowToIso(window: DateWindow): string | undefined {
  if (window === "all") return undefined
  const days = window === "7d" ? 7 : window === "30d" ? 30 : 90
  const d = new Date()
  d.setDate(d.getDate() - days)
  return d.toISOString()
}

function isFiltered(filters: AuditFilters): boolean {
  return !!(filters.q || filters.action || filters.resourceType)
}

type LoadState = "loading" | "ok" | "error"

export function AuditContent() {
  const [filters, setFilters] = useState<AuditFilters>({
    dateWindow: "7d",
    q: "",
    action: "",
    resourceType: "",
  })
  // Typed immediately for a responsive input; debounced into filters.q, which
  // is what drives the server-side query.
  const [searchInput, setSearchInput] = useState("")
  const [page, setPage] = useState(1)

  // Distinct action/resource vocabularies for the filter pickers, from the
  // whole log — not just the current page.
  const [actionOptions, setActionOptions] = useState<string[]>([])
  const [resourceTypeOptions, setResourceTypeOptions] = useState<string[]>([])

  const [events, setEvents] = useState<AuditEvent[]>([])
  const [total, setTotal] = useState(0)
  const [loadState, setLoadState] = useState<LoadState>("loading")
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [errorStatus, setErrorStatus] = useState<number | null>(null)

  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters((prev) => (prev.q === searchInput ? prev : { ...prev, q: searchInput }))
    }, SEARCH_DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [searchInput])

  // Any committed filter change restarts paging from the first page.
  useEffect(() => {
    setPage(1)
  }, [filters.q, filters.dateWindow, filters.action, filters.resourceType])

  // Facet vocabularies are optional chrome — if they fail to load, free-text
  // search still works, so swallow the error rather than blocking the page.
  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const facets = await listAuditFacets()
        if (cancelled) return
        setActionOptions(facets.actions)
        setResourceTypeOptions(facets.resource_types)
      } catch {
        /* ignore */
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  const load = useCallback(async () => {
    setLoadState("loading")
    setErrorMessage(null)
    setErrorStatus(null)
    const query: AuditQueryFilters = {
      limit: PER_PAGE,
      offset: (page - 1) * PER_PAGE,
      since: windowToIso(filters.dateWindow),
      ...(filters.q ? { q: filters.q } : {}),
      ...(filters.action ? { action: filters.action } : {}),
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

  function openDrawer(event: AuditEvent) {
    setSelectedEvent(event)
    setDrawerOpen(true)
  }

  return (
    <>
      <div className="space-y-6">
        {/* Filter bar */}
        <AuditCommandBar
          dateWindow={filters.dateWindow}
          onDateWindowChange={(v) => setFilters((prev) => ({ ...prev, dateWindow: v }))}
          search={searchInput}
          onSearchChange={setSearchInput}
          onSearchSubmit={() =>
            setFilters((prev) => (prev.q === searchInput ? prev : { ...prev, q: searchInput }))
          }
          action={filters.action}
          onActionChange={(v) => setFilters((prev) => ({ ...prev, action: v }))}
          resourceType={filters.resourceType}
          onResourceTypeChange={(v) => setFilters((prev) => ({ ...prev, resourceType: v }))}
          actionOptions={actionOptions}
          resourceTypeOptions={resourceTypeOptions}
        />

        {/* Error state */}
        {loadState === "error" && (
          <div className="rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface)] p-8">
            <p className="text-sm font-semibold text-[var(--color-severity-critical-text)]">
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
