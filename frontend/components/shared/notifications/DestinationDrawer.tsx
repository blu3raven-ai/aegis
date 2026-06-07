"use client"

import { useEffect, useState } from "react"
import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import { DrawerHeader } from "@/components/shared/FindingDrawer/DrawerHeader"
import { DrawerSection } from "@/components/shared/FindingDrawer/DrawerSection"
import type {
  NotificationDestination,
  NotificationDelivery,
  UpdateDestinationPayload,
} from "@/lib/client/destinations-api"
import { listDeliveries, updateDestination } from "@/lib/client/destinations-api"
import { DestinationForm } from "./DestinationForm"
import { DeliveriesHistoryList } from "./DeliveriesHistoryList"
import { DestinationTypeIcon } from "./DestinationTypeIcon"
import { WebhookSigningPanel } from "./WebhookSigningPanel"

interface DestinationDrawerProps {
  destination: NotificationDestination | null
  orgId: string
  open: boolean
  onClose: () => void
  onUpdated: (dest: NotificationDestination) => void
}

// Only these three types map to form fields in DestinationForm; catalog-created
// destinations can have arbitrary types that the form doesn't understand.
const EDITABLE_TYPES = new Set(["slack", "webhook", "email"])

export function DestinationDrawer({
  destination,
  orgId,
  open,
  onClose,
  onUpdated,
}: DestinationDrawerProps) {
  const isWebhook = destination?.destination_type === "webhook"
  const isEditable = destination ? EDITABLE_TYPES.has(destination.destination_type) : false
  const [tab, setTab] = useState<"details" | "signing" | "history">("details")
  const [editing, setEditing] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)

  const [deliveries, setDeliveries] = useState<NotificationDelivery[]>([])
  const [deliveriesLoading, setDeliveriesLoading] = useState(false)
  const [deliveriesError, setDeliveriesError] = useState<string | null>(null)

  // Reset state on new destination
  useEffect(() => {
    if (open && destination) {
      setTab("details")
      setEditing(false)
      setSubmitError(null)
    }
  }, [open, destination?.id])

  // Load delivery history lazily when tab switches
  useEffect(() => {
    if (tab !== "history" || !destination) return
    setDeliveriesLoading(true)
    setDeliveriesError(null)
    listDeliveries(destination.id, 25)
      .then((rows) => setDeliveries(rows))
      .catch((err: Error) => setDeliveriesError(err.message))
      .finally(() => setDeliveriesLoading(false))
  }, [tab, destination?.id])

  async function handleUpdate(
    payload: UpdateDestinationPayload & { id: number },
  ) {
    setSubmitting(true)
    setSubmitError(null)
    try {
      const updated = await updateDestination(payload.id, payload)
      onUpdated(updated)
      setEditing(false)
    } catch (err: unknown) {
      setSubmitError(err instanceof Error ? err.message : "Failed to save changes")
    } finally {
      setSubmitting(false)
    }
  }

  if (!destination) return null

  const typeLabel =
    destination.destination_type.charAt(0).toUpperCase() +
    destination.destination_type.slice(1)

  return (
    <FindingsDrawerShell
      open={open}
      onClose={onClose}
      label={`Destination: ${destination.name}`}
    >
      <DrawerHeader
        eyebrow="Notification destination"
        title={destination.name}
        identifier={`ID ${destination.id} · ${typeLabel}`}
        badges={
          <span className="flex items-center gap-1.5">
            <DestinationTypeIcon type={destination.destination_type} />
            <span
              className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold ${
                destination.enabled
                  ? "bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok)]"
                  : "bg-[var(--color-border)] text-[var(--color-text-tertiary)]"
              }`}
            >
              {destination.enabled ? "Active" : "Disabled"}
            </span>
          </span>
        }
        onClose={onClose}
      />

      {/* Tab bar */}
      <div className="flex border-b border-[var(--color-border)] px-5">
        {([
          "details",
          ...(isWebhook ? (["signing"] as const) : []),
          "history",
        ] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t as typeof tab)}
            className={`mr-4 py-3 text-xs font-semibold capitalize transition-colors focus-visible:outline-none ${
              tab === t
                ? "border-b-2 border-[var(--color-accent)] text-[var(--color-text-primary)]"
                : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            {t === "history" ? "Delivery history" : t === "signing" ? "Signing" : "Details"}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {tab === "details" && (
          <>
            {editing && isEditable ? (
              <DrawerSection label="Edit destination">
                {submitError && (
                  <p className="mb-3 text-sm text-[var(--color-severity-critical)]">{submitError}</p>
                )}
                <DestinationForm
                  initial={destination}
                  orgId={orgId}
                  onSubmit={(payload) => handleUpdate(payload as UpdateDestinationPayload & { id: number })}
                  onCancel={() => setEditing(false)}
                  submitting={submitting}
                />
              </DrawerSection>
            ) : (
              <>
                <DrawerSection
                  label="Configuration"
                  action={
                    isEditable ? (
                      <button
                        type="button"
                        onClick={() => setEditing(true)}
                        className="text-xs font-semibold text-[var(--color-accent)] hover:underline focus-visible:outline-none"
                      >
                        Edit
                      </button>
                    ) : undefined
                  }
                >
                  <dl className="space-y-3">
                    <div>
                      <dt className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
                        Type
                      </dt>
                      <dd className="mt-0.5 flex items-center gap-1.5 text-sm text-[var(--color-text-primary)] capitalize">
                        <DestinationTypeIcon type={destination.destination_type} />
                        {destination.destination_type}
                      </dd>
                    </div>

                    {destination.destination_type === "slack" &&
                      typeof destination.config.webhook_url === "string" && (
                        <div>
                          <dt className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
                            Webhook URL
                          </dt>
                          <dd className="mt-0.5 break-all font-mono text-xs text-[var(--color-text-primary)]">
                            {destination.config.webhook_url}
                          </dd>
                        </div>
                      )}

                    {destination.destination_type === "webhook" &&
                      typeof destination.config.url === "string" && (
                        <div>
                          <dt className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
                            URL
                          </dt>
                          <dd className="mt-0.5 break-all font-mono text-xs text-[var(--color-text-primary)]">
                            {destination.config.url}
                          </dd>
                        </div>
                      )}

                    {destination.destination_type === "email" &&
                      Array.isArray(destination.config.to_addresses) && (
                        <div>
                          <dt className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
                            Recipients
                          </dt>
                          <dd className="mt-0.5 space-y-0.5">
                            {(destination.config.to_addresses as string[]).map((addr) => (
                              <p key={addr} className="text-sm text-[var(--color-text-primary)]">
                                {addr}
                              </p>
                            ))}
                          </dd>
                        </div>
                      )}
                  </dl>
                </DrawerSection>

                {!isEditable && (
                  <p className="text-xs text-[var(--color-text-secondary)]">
                    This destination type can&apos;t be edited in-place. Delete and re-create to change its configuration.
                  </p>
                )}

                <DrawerSection label="Event filter">
                  <dl className="space-y-3">
                    <div>
                      <dt className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
                        Min severity
                      </dt>
                      <dd className="mt-0.5 text-sm capitalize text-[var(--color-text-primary)]">
                        {destination.event_filter?.min_severity ?? "All"}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
                        Event types
                      </dt>
                      <dd className="mt-1 flex flex-wrap gap-1.5">
                        {destination.event_filter?.event_types &&
                        destination.event_filter.event_types.length > 0 ? (
                          destination.event_filter.event_types.map((et) => (
                            <span
                              key={et}
                              className="rounded-md border border-[var(--color-border)] px-2 py-0.5 text-xs text-[var(--color-text-secondary)]"
                            >
                              {et}
                            </span>
                          ))
                        ) : (
                          <span className="text-sm text-[var(--color-text-secondary)]">All events</span>
                        )}
                      </dd>
                    </div>
                  </dl>
                </DrawerSection>
              </>
            )}
          </>
        )}

        {tab === "signing" && isWebhook && (
          <DrawerSection label="HMAC signing">
            <WebhookSigningPanel destId={destination.id} />
          </DrawerSection>
        )}

        {tab === "history" && (
          <DrawerSection label="Recent deliveries">
            <DeliveriesHistoryList
              deliveries={deliveries}
              loading={deliveriesLoading}
              error={deliveriesError ?? undefined}
            />
          </DrawerSection>
        )}
      </div>
    </FindingsDrawerShell>
  )
}
