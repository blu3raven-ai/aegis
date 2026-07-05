"use client"

import { useCallback, useEffect, useMemo, useState } from "react"

import { getCatalog, type ConnectorType } from "@/lib/client/integrations-catalog-api"
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
import { PageHeader } from "@/components/layout/PageHeader"
import { useLicense } from "@/lib/client/license/client"

import { IntegrationsIcon } from "./_connectors"
import { IntegrationsChannelsTab } from "./IntegrationsChannelsTab"
import { IntegrationsBrowseTab } from "./IntegrationsBrowseTab"
import { IntegrationsRoutingTab } from "./IntegrationsRoutingTab"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

const TABS = ["channels", "browse", "routing"] as const
type IntegrationsTab = (typeof TABS)[number]

const TAB_LABEL: Record<IntegrationsTab, string> = {
  channels: "Channels",
  browse: "Browse",
  routing: "Routing",
}

export function IntegrationsContent() {
  const [activeTab, setActiveTab] = useState<IntegrationsTab>("channels")

  const { tier } = useLicense()
  const isEnterprise = tier === "enterprise"

  const [catalog, setCatalog] = useState<ConnectorType[]>([])
  const [catalogState, setCatalogState] = useState<"loading" | "ok" | "error">("loading")

  const [destinations, setDestinations] = useState<NotificationDestination[]>([])
  const [destsState, setDestsState] = useState<"loading" | "ok" | "error">("loading")

  const [selectedDest, setSelectedDest] = useState<NotificationDestination | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)

  const [creatingDest, setCreatingDest] = useState(false)
  const [createSubmitting, setCreateSubmitting] = useState(false)
  const [createError, setCreateError] = useState<string | null>(null)

  const [deletingId, setDeletingId] = useState<number | null>(null)
  const [testStatuses, setTestStatuses] = useState<Record<number, TestStatus>>({})

  const loadCatalog = useCallback(() => {
    setCatalogState("loading")
    getCatalog()
      .then((d) => { setCatalog(d.connectors); setCatalogState("ok") })
      .catch(() => setCatalogState("error"))
  }, [])

  const loadDestinations = useCallback(() => {
    setDestsState("loading")
    listDestinations(ORG_ID)
      .then((rows) => { setDestinations(rows); setDestsState("ok") })
      .catch(() => setDestsState("error"))
  }, [])

  useEffect(() => {
    loadCatalog()
    loadDestinations()
  }, [loadCatalog, loadDestinations])

  const selectTab = useCallback((tab: IntegrationsTab) => {
    // Clear overlay state when switching tabs so stale UI does not re-appear
    setDrawerOpen(false)
    setSelectedDest(null)
    setCreatingDest(false)
    setActiveTab(tab)
  }, [])

  const handleCreate = useCallback(
    async (
      payload: CreateDestinationPayload | (UpdateDestinationPayload & { id: number }),
    ) => {
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
      const result: TestSendResult = await testDestination(dest.id, ORG_ID)
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

  const handleStartCreate = useCallback(() => {
    setCreatingDest(true)
    setDrawerOpen(false)
    setSelectedDest(null)
  }, [])

  const handleCancelCreate = useCallback(() => {
    setCreatingDest(false)
    setCreateError(null)
  }, [])

  const handleRowOpen = useCallback((dest: NotificationDestination) => {
    setSelectedDest(dest)
    setDrawerOpen(true)
  }, [])

  const handleDestinationCreated = useCallback((dest: NotificationDestination) => {
    setDestinations((prev) => [...prev, dest])
  }, [])

  // Connected channel count powers the tab badge so users see configured state at a glance.
  const connectedCount = useMemo(() => destinations.length, [destinations])

  return (
    <div>
      <PageHeader
        icon={<IntegrationsIcon />}
        title="Integrations"
        description="Connect Aegis to external tools and services"
      />

      <nav
        role="tablist"
        aria-label="Integrations sections"
        className="border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 flex"
      >
        {TABS.map((tab) => {
          const active = activeTab === tab
          return (
            <button
              key={tab}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => selectTab(tab)}
              className={`-mb-px border-b-2 px-3 py-2.5 text-sm transition-colors ${
                active
                  ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
                  : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              {TAB_LABEL[tab]}
              {tab === "channels" && destsState === "ok" && connectedCount > 0 && (
                <span
                  className={`ml-2 rounded-full px-1.5 py-0.5 text-2xs font-semibold tabular-nums ${
                    active
                      ? "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                      : "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]"
                  }`}
                >
                  {connectedCount}
                </span>
              )}
            </button>
          )
        })}
      </nav>

      {activeTab === "channels" && (
        <IntegrationsChannelsTab
          orgId={ORG_ID}
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
      )}

      {activeTab === "browse" && (
        <IntegrationsBrowseTab
          catalog={catalog}
          catalogState={catalogState}
          destinations={destinations}
          isEnterprise={isEnterprise}
          onReload={loadCatalog}
          onDestinationCreated={handleDestinationCreated}
        />
      )}

      {activeTab === "routing" && (
        <IntegrationsRoutingTab orgId={ORG_ID} keyHint={destinations.length} />
      )}

      {/* Destination detail drawer — shared across tabs so deep-linking works */}
      {drawerOpen && (
        <div
          className="fixed inset-0 z-30 bg-[var(--color-overlay)]"
          onClick={() => setDrawerOpen(false)}
          aria-hidden="true"
        />
      )}
      <DestinationDrawer
        destination={selectedDest}
        orgId={ORG_ID}
        open={drawerOpen}
        onClose={() => { setDrawerOpen(false); setSelectedDest(null) }}
        onUpdated={handleUpdated}
      />
    </div>
  )
}
