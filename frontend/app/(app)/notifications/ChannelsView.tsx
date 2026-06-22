"use client"

import { useMemo } from "react"

import { DestinationsTable, type TestStatus } from "@/components/shared/notifications/DestinationsTable"
import { DestinationForm } from "@/components/shared/notifications/DestinationForm"
import { EmptyDestinationsState } from "@/components/shared/notifications/EmptyDestinationsState"
import { DrawerSection } from "@/components/shared/FindingDrawer/DrawerSection"
import { KpiCard } from "@/components/shared/KpiCard"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Sheet } from "@/components/ui/Sheet"
import { Skeleton } from "@/components/ui/Skeleton"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import {
  type NotificationDestination,
  type CreateDestinationPayload,
  type UpdateDestinationPayload,
} from "@/lib/client/destinations-api"

interface ChannelsViewProps {
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
    <Card padding="none" className="overflow-hidden rounded-2xl">
      <Table>
        <Thead>
          <Tr>
            {["Name", "Type", "Status", "Filters", "Last updated", "Actions"].map((h) => (
              <Th key={h}>{h}</Th>
            ))}
          </Tr>
        </Thead>
        <Tbody>
          {[1, 2, 3].map((i) => (
            <Tr key={i}>
              {[1, 2, 3, 4, 5, 6].map((j) => (
                <Td key={j}>
                  <Skeleton className="h-4 w-full" />
                </Td>
              ))}
            </Tr>
          ))}
        </Tbody>
      </Table>
    </Card>
  )
}

const NEUTRAL = "text-[var(--color-text-primary)]"

// Stats strip — backend does not yet expose aggregate delivery/event/ticket counters,
// so we surface the one real metric we have (configured channel count) and mark the
// rest as deferred placeholders rather than fabricating numbers. Strip mirrors the
// Compliance pattern: sits inside the page body without its own surface treatment,
// so the KpiCard primitives provide the only visual lift.
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
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-2 lg:grid-cols-4">
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

export function ChannelsView({
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
}: ChannelsViewProps) {
  return (
    <>
      <div className="space-y-8 px-6 py-8">
        <StatsStrip destinations={destinations} />

        <section>
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-base font-semibold text-[var(--color-text-primary)]">Destinations</h2>
            <Button variant="primary" size="sm" onClick={onStartCreate}>
              Add destination
            </Button>
          </div>

          {destsState === "loading" && <DestinationsLoadingSkeleton />}
          {destsState === "error" && (
            <div className="flex items-center gap-3 text-sm text-[var(--color-severity-high)]">
              <span>Failed to load destinations.</span>
              <Button variant="ghost" size="xs" onClick={onReload}>
                Retry
              </Button>
            </div>
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
      </div>

      <Sheet
        open={creatingDest}
        onClose={onCancelCreate}
        title="New destination"
        description="Configure a notification destination."
        size="md"
      >
        <DrawerSection label="New destination">
          {createError && (
            <p
              role="alert"
              className="mb-3 text-sm text-[var(--color-severity-critical)]"
            >
              {createError}
            </p>
          )}
          <DestinationForm
            initial={null}
            onSubmit={onCreate}
            onCancel={onCancelCreate}
            submitting={createSubmitting}
          />
        </DrawerSection>
      </Sheet>
    </>
  )
}
