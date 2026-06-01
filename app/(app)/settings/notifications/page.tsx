"use client"

import { useCallback, useEffect, useState } from "react"
import type {
  NotificationDestination,
  CreateDestinationPayload,
  UpdateDestinationPayload,
} from "@/lib/client/destinations-api"
import {
  listDestinations,
  createDestination,
  deleteDestination,
  testDestination,
} from "@/lib/client/destinations-api"
import { DestinationsTable, type TestStatus } from "@/components/shared/notifications/DestinationsTable"
import { DestinationDrawer } from "@/components/shared/notifications/DestinationDrawer"
import { DestinationForm } from "@/components/shared/notifications/DestinationForm"
import { EmptyDestinationsState } from "@/components/shared/notifications/EmptyDestinationsState"
import { DrawerSection } from "@/components/shared/FindingDrawer/DrawerSection"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

export default function NotificationsPage() {
  const orgId = ORG_ID
  const [destinations, setDestinations] = useState<NotificationDestination[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)

  // Drawer state
  const [selectedDest, setSelectedDest] = useState<NotificationDestination | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)

  // Create form overlay
  const [creating, setCreating] = useState(false)
  const [createSubmitting, setCreateSubmitting] = useState(false)
  const [createError, setCreateError] = useState<string | null>(null)

  // Delete
  const [deletingId, setDeletingId] = useState<number | null>(null)

  // Per-destination test-send state
  const [testStatuses, setTestStatuses] = useState<Record<number, TestStatus>>({})

  const loadAll = useCallback(() => {
    setLoading(true)
    setLoadError(null)
    listDestinations(orgId)
      .then((rows) => setDestinations(rows))
      .catch((err: Error) => {
        setLoadError(err.message)
      })
      .finally(() => setLoading(false))
  }, [orgId])

  useEffect(() => {
    loadAll()
  }, [loadAll])

  async function handleCreate(payload: CreateDestinationPayload | (UpdateDestinationPayload & { id: number })) {
    setCreateSubmitting(true)
    setCreateError(null)
    try {
      const created = await createDestination(payload as CreateDestinationPayload)
      setDestinations((prev) => [created, ...prev])
      setCreating(false)
    } catch (err: unknown) {
      setCreateError(err instanceof Error ? err.message : "Failed to create destination")
    } finally {
      setCreateSubmitting(false)
    }
  }

  async function handleTest(dest: NotificationDestination) {
    setTestStatuses((prev) => ({ ...prev, [dest.id]: { kind: "sending" } }))
    try {
      const result = await testDestination(dest.id, orgId)
      setTestStatuses((prev) => ({
        ...prev,
        [dest.id]:
          result.status === "delivered"
            ? { kind: "delivered", latency_ms: result.latency_ms }
            : { kind: "failed", error: result.error ?? "Delivery failed" },
      }))
    } catch (err: unknown) {
      setTestStatuses((prev) => ({
        ...prev,
        [dest.id]: {
          kind: "failed",
          error: err instanceof Error ? err.message : "Test send failed",
        },
      }))
    }
  }

  async function handleDelete(dest: NotificationDestination) {
    if (!window.confirm(`Delete "${dest.name}"? This cannot be undone.`)) return
    setDeletingId(dest.id)
    try {
      await deleteDestination(dest.id)
      setDestinations((prev) => prev.filter((d) => d.id !== dest.id))
      if (selectedDest?.id === dest.id) setDrawerOpen(false)
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : "Failed to delete destination")
    } finally {
      setDeletingId(null)
    }
  }

  function handleUpdated(updated: NotificationDestination) {
    setDestinations((prev) => prev.map((d) => (d.id === updated.id ? updated : d)))
    setSelectedDest(updated)
  }

  function openDrawer(dest: NotificationDestination) {
    setSelectedDest(dest)
    setDrawerOpen(true)
    setCreating(false)
  }

  function openEdit(dest: NotificationDestination) {
    setSelectedDest(dest)
    setDrawerOpen(true)
    setCreating(false)
  }

  return (
    <>
      <div className="mx-auto max-w-5xl p-6 lg:p-10 space-y-6">
        {/* Page header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-lg font-semibold tracking-tight text-[var(--color-text-primary)]">
              Notification destinations
            </h1>
            <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
              Route critical events to Slack, webhooks, or email.
            </p>
          </div>
          {!loading && !loadError && (
            <button
              type="button"
              onClick={() => { setCreating(true); setDrawerOpen(false) }}
              className="shrink-0 rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)]"
            >
              + Add destination
            </button>
          )}
        </div>

        {/* Create form panel */}
        {creating && (
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6">
            <DrawerSection label="New destination">
              {createError && (
                <p className="mb-3 text-sm text-[var(--color-severity-critical)]">{createError}</p>
              )}
              <DestinationForm
                initial={null}
                orgId={orgId}
                onSubmit={handleCreate}
                onCancel={() => { setCreating(false); setCreateError(null) }}
                submitting={createSubmitting}
              />
            </DrawerSection>
          </div>
        )}

        {/* Error state */}
        {loadError && (
          <div className="rounded-2xl border border-[var(--color-border-strong)] bg-[var(--color-surface)] p-8">
            <p className="text-sm font-semibold text-[var(--color-severity-critical)]">
              Couldn&apos;t load destinations
            </p>
            <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
              {loadError.includes("notifications") || loadError.includes("403")
                ? "Notifications may be disabled. Set AEGIS_NOTIFICATIONS_ENABLED=true to enable."
                : loadError}
            </p>
            <button
              type="button"
              onClick={loadAll}
              className="mt-4 rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)]"
            >
              Retry
            </button>
          </div>
        )}

        {/* Main content */}
        {!loadError && !loading && destinations.length === 0 && !creating && (
          <EmptyDestinationsState onAdd={() => setCreating(true)} />
        )}

        {!loadError && (loading || destinations.length > 0) && (
          <DestinationsTable
            destinations={destinations}
            loading={loading}
            onRowClick={openDrawer}
            onEdit={openEdit}
            onDelete={handleDelete}
            onTest={handleTest}
            testStatuses={testStatuses}
            deletingId={deletingId}
          />
        )}

        {/* Help note */}
        {!loadError && !loading && destinations.length > 0 && (
          <p className="text-[11px] text-[var(--color-text-tertiary)]">
            Click a row to inspect configuration and delivery history.
            Use Test to send a sample notification to that destination.
          </p>
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
      <DestinationDrawer
        destination={selectedDest}
        orgId={orgId}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        onUpdated={handleUpdated}
      />
    </>
  )
}
