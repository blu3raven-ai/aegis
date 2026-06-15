"use client"

import { useState } from "react"
import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import { DrawerHeader } from "@/components/shared/FindingDrawer/DrawerHeader"
import { DrawerDetailGrid } from "@/components/shared/FindingDrawer/DrawerDetailGrid"
import { DrawerSection } from "@/components/shared/FindingDrawer/DrawerSection"
import { ActionBadge } from "./ActionBadge"
import { ActorBadge } from "./ActorBadge"
import { ChangesDiffTable } from "./ChangesDiffTable"
import type { AuditEvent } from "@/lib/client/audit-api"
import { Button } from "@/components/ui/Button"

function formatTimestamp(iso: string): string {
  try {
    return new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "long" }).format(new Date(iso))
  } catch {
    return iso
  }
}

interface AuditEventDrawerProps {
  event: AuditEvent | null
  open: boolean
  onClose: () => void
}

export function AuditEventDrawer({ event, open, onClose }: AuditEventDrawerProps) {
  const [rawExpanded, setRawExpanded] = useState(false)

  if (!event) {
    return (
      <FindingsDrawerShell open={open} onClose={onClose} label="Audit event details">
        <div />
      </FindingsDrawerShell>
    )
  }

  const detailItems = [
    { label: "Resource type", value: event.resource_type },
    { label: "Resource ID", value: event.resource_id ?? "—" },
    { label: "Status code", value: event.status_code != null ? String(event.status_code) : "—" },
    { label: "Method", value: event.request_method ?? "—" },
    { label: "IP address", value: event.request_ip ?? "—" },
    { label: "Path", value: event.request_path ?? "—" },
  ].filter((item) => item.value !== "—" || item.label === "Resource type")

  return (
    <FindingsDrawerShell open={open} onClose={onClose} label="Audit event details">
      <DrawerHeader
        eyebrow="Audit event"
        title={event.action}
        identifier={`#${event.id} · ${formatTimestamp(event.occurred_at)}`}
        badges={<ActionBadge action={event.action} />}
        onClose={onClose}
      />

      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        <DrawerSection label="Actor">
          <ActorBadge actorId={event.actor_id} actorEmail={event.actor_email} actorRole={event.actor_role} />
        </DrawerSection>

        <DrawerSection label="Details">
          <DrawerDetailGrid items={detailItems} />
        </DrawerSection>

        {event.user_agent && (
          <DrawerSection label="User agent">
            <p className="break-words text-xs font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-secondary)]">
              {event.user_agent}
            </p>
          </DrawerSection>
        )}

        {event.changes && Object.keys(event.changes).length > 0 && (
          <DrawerSection label="Changes">
            <ChangesDiffTable changes={event.changes} />
          </DrawerSection>
        )}

        <DrawerSection
          label="Raw payload"
          action={
            <Button
              variant="link"
              size="xs"
              onClick={() => setRawExpanded((v) => !v)}
              className="text-[var(--color-accent)] font-semibold hover:opacity-80 hover:text-[var(--color-accent)]"
            >
              {rawExpanded ? "Collapse" : "Expand"}
            </Button>
          }
        >
          {rawExpanded ? (
            <pre className="overflow-x-auto rounded-lg bg-[var(--color-bg-section)] p-3 text-[11px] font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-secondary)] whitespace-pre-wrap break-all">
              {JSON.stringify(event, null, 2)}
            </pre>
          ) : (
            <p className="text-xs text-[var(--color-text-tertiary)] italic">
              Click Expand to view the full event payload.
            </p>
          )}
        </DrawerSection>
      </div>
    </FindingsDrawerShell>
  )
}
