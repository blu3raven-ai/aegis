"use client"

import { useCallback, useEffect, useState } from "react"

import {
  listDestinations,
  createDestination,
  deleteDestination,
  testDestination,
  type NotificationDestination,
  type CreateDestinationPayload,
  type UpdateDestinationPayload,
  type TestSendResult,
} from "@/lib/client/destinations-api"
import { type TestStatus } from "@/components/shared/notifications/DestinationsTable"
import { DestinationDrawer } from "@/components/shared/notifications/DestinationDrawer"

import { ChannelsView } from "../ChannelsView"

export default function ChannelsPage() {
  const [destinations, setDestinations] = useState<NotificationDestination[]>([])
  const [destsState, setDestsState] = useState<"loading" | "ok" | "error">("loading")

  const [selectedDest, setSelectedDest] = useState<NotificationDestination | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)

  const [creatingDest, setCreatingDest] = useState(false)
  const [createSubmitting, setCreateSubmitting] = useState(false)
  const [createError, setCreateError] = useState<string | null>(null)

  const [deletingId, setDeletingId] = useState<number | null>(null)
  const [testStatuses, setTestStatuses] = useState<Record<number, TestStatus>>({})

  const loadDestinations = useCallback(() => {
    setDestsState("loading")
    listDestinations()
      .then((rows) => { setDestinations(rows); setDestsState("ok") })
      .catch(() => setDestsState("error"))
  }, [])

  useEffect(() => {
    loadDestinations()
  }, [loadDestinations])

  const handleCreate = useCallback(
    async (payload: CreateDestinationPayload | (UpdateDestinationPayload & { id: number })) => {
      setCreateSubmitting(true)
      setCreateError(null)
      try {
        const created = await createDestination(payload as CreateDestinationPayload)
        setDestinations((prev) => [created, ...prev])
        setCreatingDest(false)
      } catch (err: unknown) {
        setCreateError(err instanceof Error ? err.message : "Failed to create destination")
      } finally {
        setCreateSubmitting(false)
      }
    },
    [],
  )

  const handleTest = useCallback(async (dest: NotificationDestination) => {
    setTestStatuses((prev) => ({ ...prev, [dest.id]: { kind: "sending" } }))
    try {
      const result: TestSendResult = await testDestination(dest.id)
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
  }, [])

  const handleDelete = useCallback(
    async (dest: NotificationDestination) => {
      if (!window.confirm(`Delete "${dest.name}"? This cannot be undone.`)) return
      setDeletingId(dest.id)
      try {
        await deleteDestination(dest.id)
        setDestinations((prev) => prev.filter((d) => d.id !== dest.id))
        if (selectedDest?.id === dest.id) {
          setDrawerOpen(false)
          setSelectedDest(null)
        }
      } catch (err: unknown) {
        alert(err instanceof Error ? err.message : "Failed to delete destination")
      } finally {
        setDeletingId(null)
      }
    },
    [selectedDest],
  )

  const handleUpdated = useCallback((updated: NotificationDestination) => {
    setDestinations((prev) => prev.map((d) => (d.id === updated.id ? updated : d)))
    setSelectedDest(updated)
  }, [])

  const handleRowOpen = useCallback((dest: NotificationDestination) => {
    setSelectedDest(dest)
    setDrawerOpen(true)
  }, [])

  const handleStartCreate = useCallback(() => {
    setCreatingDest(true)
    setDrawerOpen(false)
    setSelectedDest(null)
  }, [])

  const handleCancelCreate = useCallback(() => {
    setCreatingDest(false)
    setCreateError(null)
  }, [])

  return (
    <>
      <ChannelsView
        destinations={destinations}
        destsState={destsState}
        deletingId={deletingId}
        testStatuses={testStatuses}
        creatingDest={creatingDest}
        createSubmitting={createSubmitting}
        createError={createError}
        onReload={loadDestinations}
        onCreate={handleCreate}
        onRowClick={handleRowOpen}
        onEdit={handleRowOpen}
        onDelete={handleDelete}
        onTest={handleTest}
        onStartCreate={handleStartCreate}
        onCancelCreate={handleCancelCreate}
      />

      {/* Destination detail drawer */}
      {drawerOpen && (
        <div
          className="fixed inset-0 z-30 bg-[var(--color-overlay)]"
          onClick={() => setDrawerOpen(false)}
          aria-hidden="true"
        />
      )}
      <DestinationDrawer
        destination={selectedDest}
        open={drawerOpen}
        onClose={() => { setDrawerOpen(false); setSelectedDest(null) }}
        onUpdated={handleUpdated}
      />
    </>
  )
}
