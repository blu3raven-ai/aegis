"use client"

import { useMemo } from "react"

import { DestinationsTable, type TestStatus } from "@/components/shared/notifications/DestinationsTable"
import { DestinationForm } from "@/components/shared/notifications/DestinationForm"
import { EmptyDestinationsState } from "@/components/shared/notifications/EmptyDestinationsState"
import { DrawerSection } from "@/components/shared/FindingDrawer/DrawerSection"
import { KpiCard } from "@/components/shared/KpiCard"
import {
  type NotificationDestination,
  type CreateDestinationPayload,
  type UpdateDestinationPayload,
} from "@/lib/client/destinations-api"

interface IntegrationsChannelsTabProps {
  orgId: string
  destinations: NotificationDestination[]
  destsState: "loading" | "ok" | "error"
  deletingId: number | null
  testStatuses: Record<number, TestStatus>
  creatingDest: boolean
  createSubmitting: boolean
  createError: string | null
  onReload: () => void
  onCreate: (
    payload: CreateDestinationPayload | (UpdateDestinationPayload & { id: number }),
  ) => Promise<void>
  onRowClick: (dest: NotificationDestination) => void
  onEdit: (dest: NotificationDestination) => void
  onDelete: (dest: NotificationDestination) => void
  onTest: (dest: NotificationDestination) => void
  onStartCreate: () => void
  onCancelCreate: () => void
}

function DestinationsLoadingSkeleton() {
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
          {[1, 2, 3].map((i) => (
            <tr key={i}>
              {[1, 2, 3, 4, 5, 6].map((j) => (
                <td key={j} className="px-4 py-3">
                  <div className="h-4 w-full animate-pulse rounded bg-[var(--color-surface-raised)]" />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const NEUTRAL = "text-[var(--color-text-primary)]"

// Stats strip — backend does not yet expose aggregate delivery/event/ticket counters,
// so we surface the one real metric we have (configured channel count) and mark the
// rest as deferred placeholders rather than fabricating numbers.
function StatsStrip({ destinations }: { destinations: NotificationDestination[] }) {
  const stats = useMemo(() => {
    const channelCount = destinations.filter((d) => d.enabled).length
    return {
      channelCount,
      enabled: channelCount > 0,
    }
  }, [destinations])

  const unavailableHint = stats.enabled ? "Available after first delivery" : "Configure a channel to enable"

  return (
    <div className="grid grid-cols-2 gap-3 border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-4 sm:grid-cols-2 lg:grid-cols-4">
      <KpiCard
        label="Channels configured"
        value={String(stats.channelCount)}
        note={stats.channelCount === 1 ? "1 enabled destination" : `${stats.channelCount} enabled destinations`}
        valueClass={NEUTRAL}
      />
      <KpiCard label="Events sent (24h)" value="—" note={unavailableHint} valueClass={NEUTRAL} />
      <KpiCard label="Jira tickets created" value="—" note={unavailableHint} valueClass={NEUTRAL} />
      <KpiCard label="Fix PRs opened" value="—" note={unavailableHint} valueClass={NEUTRAL} />
    </div>
  )
}

export function IntegrationsChannelsTab({
  orgId,
  destinations,
  destsState,
  deletingId,
  testStatuses,
  creatingDest,
  createSubmitting,
  createError,
  onReload,
  onCreate,
  onRowClick,
  onEdit,
  onDelete,
  onTest,
  onStartCreate,
  onCancelCreate,
}: IntegrationsChannelsTabProps) {
  return (
    <>
      <StatsStrip destinations={destinations} />

      <div className="px-6 py-8 space-y-8">

      <section>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Destinations</h2>
          <button
            type="button"
            onClick={onStartCreate}
            className="rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)]"
          >
            + Add destination
          </button>
        </div>

        {destsState === "loading" && <DestinationsLoadingSkeleton />}
        {destsState === "error" && (
          <p className="text-sm text-[var(--color-severity-high)]">
            Failed to load destinations.{" "}
            <button type="button" onClick={onReload} className="underline">
              Retry
            </button>
          </p>
        )}
        {destsState === "ok" && destinations.length === 0 && (
          <EmptyDestinationsState onAdd={onStartCreate} />
        )}
        {destsState === "ok" && destinations.length > 0 && (
          <DestinationsTable
            destinations={destinations}
            deletingId={deletingId}
            testStatuses={testStatuses}
            onRowClick={onRowClick}
            onEdit={onEdit}
            onDelete={onDelete}
            onTest={onTest}
          />
        )}
      </section>

      {creatingDest && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-[var(--color-overlay)] p-4">
          <div className="w-full max-w-lg rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-xl">
            <DrawerSection label="New destination">
              {createError && (
                <p className="mb-3 text-sm text-[var(--color-severity-critical)]">{createError}</p>
              )}
              <DestinationForm
                initial={null}
                onSubmit={onCreate}
                onCancel={onCancelCreate}
                submitting={createSubmitting}
              />
            </DrawerSection>
          </div>
        </div>
      )}
      </div>
    </>
  )
}
