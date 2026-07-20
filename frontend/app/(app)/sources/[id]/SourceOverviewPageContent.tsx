"use client"

import { useEffect, useState } from "react"
import { Boxes, Clock, Plug, PlugZap, Radar, RefreshCw } from "lucide-react"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"
import { StatusPill, type Status } from "@/components/ui/StatusPill"
import { getSourceConnection } from "@/lib/client/source-connections-api"
import { useSourceId } from "@/lib/client/use-source-id"
import {
  CATEGORY_ITEM_LABELS,
  CATEGORY_SCANNERS,
  CONNECTION_METHOD_LABELS,
  SCANNER_LABELS,
  SOURCE_TYPE_LABELS,
  SYNC_SCHEDULE_LABELS,
} from "@/lib/shared/sources-types"
import type { ConnectionStatus, SourceConnection, SyncSchedule } from "@/lib/shared/sources-types"
import { timeAgo, timeUntil } from "@/lib/shared/time-ago"
import { cn } from "@/lib/shared/utils"


type Tone = "accent" | "success" | "warning" | "danger"

const TONE_CHIP: Record<Tone, string> = {
  accent:  "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]",
  success: "bg-[var(--color-state-fixed-subtle)] text-[var(--color-state-fixed-text)]",
  warning: "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending-text)]",
  danger:  "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]",
}

const TONE_VALUE: Record<Tone, string> = {
  accent:  "text-[var(--color-text-primary)]",
  success: "text-[var(--color-state-fixed-text)]",
  warning: "text-[var(--color-state-pending-text)]",
  danger:  "text-[var(--color-severity-critical-text)]",
}

/**
 * Icon-led stat tile. The leading tinted chip gives each heterogeneous value
 * (a count, an enum status, a relative time) its own scannable identity instead
 * of reading as identical number boxes. An optional secondary line lets one
 * tile carry a paired value (e.g. last synced under next sync).
 */
function StatTile({
  icon: Icon,
  label,
  value,
  secondary,
  tone = "accent",
  tabular = false,
  spin = false,
}: {
  icon: React.ComponentType<{ className?: string; "aria-hidden"?: boolean }>
  label: string
  value: string
  secondary?: string
  tone?: Tone
  tabular?: boolean
  spin?: boolean
}) {
  return (
    <div className="flex items-center gap-3 rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
      <span className={cn("grid h-9 w-9 shrink-0 place-items-center rounded-lg", TONE_CHIP[tone])}>
        <Icon className={cn("h-[18px] w-[18px]", spin && "animate-spin")} aria-hidden />
      </span>
      <div className="min-w-0">
        <div className="text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
          {label}
        </div>
        <div
          className={cn(
            "mt-1 truncate text-xl font-semibold leading-none",
            tabular && "tabular-nums",
            TONE_VALUE[tone],
          )}
          title={value}
        >
          {value}
        </div>
        {secondary && (
          <div className="mt-1 truncate text-xs text-[var(--color-text-secondary)]" title={secondary}>
            {secondary}
          </div>
        )}
      </div>
    </div>
  )
}


function statusTone(status: ConnectionStatus): Tone {
  switch (status) {
    case "connected":    return "success"
    case "syncing":      return "warning"
    case "error":        return "danger"
    case "disconnected": return "danger"
    case "not-synced":   return "accent"
  }
}

const STATUS_ICON: Record<ConnectionStatus, React.ComponentType<{ className?: string; "aria-hidden"?: boolean }>> = {
  "connected":    Plug,
  "syncing":      RefreshCw,
  "error":        PlugZap,
  "disconnected": PlugZap,
  "not-synced":   Plug,
}

const STATUS_LABEL: Record<ConnectionStatus, string> = {
  "connected":    "Connected",
  "syncing":      "Syncing",
  "error":        "Error",
  "disconnected": "Disconnected",
  "not-synced":   "Not Synced",
}

const STATUS_PILL: Record<ConnectionStatus, Status> = {
  "connected":    "healthy",
  "syncing":      "warning",
  "error":        "failing",
  "disconnected": "failing",
  "not-synced":   "stale",
}

const PRESET_HOURS: Record<SyncSchedule, number> = {
  "1h": 1, "3h": 3, "6h": 6, "12h": 12, "24h": 24,
}

/**
 * Next firing of an interval preset (e.g. every 6h fires at 00/06/12/18:00),
 * mirroring the cron the backend scheduler runs. Used to show a "next scan"
 * countdown without persisting a next-scan timestamp.
 */
function nextPresetOccurrence(preset: SyncSchedule, now: Date): Date {
  const h = PRESET_HOURS[preset]
  const next = new Date(now)
  next.setMinutes(0, 0, 0)
  do {
    next.setHours(next.getHours() + 1)
  } while (next <= now || next.getHours() % h !== 0)
  return next
}

/** Value + secondary line for the Scan stat tile, derived from the schedule. */
function scanSummary(connection: SourceConnection): { value: string; secondary?: string } {
  if (!connection.scanAutoEnabled) {
    return { value: "Manual only", secondary: "Automatic scans off" }
  }
  if (connection.scanScheduleMode === "cron") {
    return { value: "On schedule", secondary: "Custom cron" }
  }
  const next = nextPresetOccurrence(connection.scanSchedulePreset, new Date())
  return {
    value: `Next ${timeUntil(next.toISOString())}`,
    secondary: SYNC_SCHEDULE_LABELS[connection.scanSchedulePreset],
  }
}

/** Human summary of which scanners run, or null when the category has none. */
function scannersSummary(connection: SourceConnection): string | null {
  const applicable = CATEGORY_SCANNERS[connection.category]
  if (applicable.length === 0) return null
  const selected = connection.scanners.length ? connection.scanners : applicable
  if (selected.length === applicable.length) return "All scanners"
  return selected.map((s) => SCANNER_LABELS[s]).join(", ")
}


function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-2.5">
      <dt className="shrink-0 text-xs text-[var(--color-text-secondary)]">{label}</dt>
      <dd className="min-w-0 truncate text-right text-sm font-medium text-[var(--color-text-primary)]">
        {children}
      </dd>
    </div>
  )
}


function OverviewSkeleton() {
  return (
    <div className="px-6 py-6 space-y-6">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-[74px] rounded-lg" />
        ))}
      </div>
      <div className="grid gap-6 lg:grid-cols-3">
        <Skeleton className="h-64 rounded-lg lg:col-span-1" />
        <Skeleton className="h-64 rounded-lg lg:col-span-2" />
      </div>
    </div>
  )
}


export function SourceOverviewPageContent() {
  const id = useSourceId()
  const [connection, setConnection] = useState<SourceConnection | null>(null)

  useEffect(() => {
    if (!id) return
    let cancelled = false
    getSourceConnection(id).then((r) => {
      if (!cancelled && r.ok) setConnection(r.data.connection)
    })
    return () => { cancelled = true }
  }, [id])

  if (!connection) return <OverviewSkeleton />

  const itemNoun = CATEGORY_ITEM_LABELS[connection.category]
  const items = connection.discoveredItems ?? []
  const VISIBLE = 24
  const overflow = Math.max(0, items.length - VISIBLE)
  const scan = scanSummary(connection)
  const scanners = scannersSummary(connection)

  return (
    <div className="px-6 py-6 space-y-6">
      {/* Stat strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatTile
          icon={Boxes}
          label="Discovered items"
          value={connection.discoveredItemCount != null ? connection.discoveredItemCount.toLocaleString() : "—"}
          tabular
        />
        <StatTile
          icon={STATUS_ICON[connection.status]}
          label="Connection status"
          value={STATUS_LABEL[connection.status]}
          tone={statusTone(connection.status)}
          spin={connection.status === "syncing"}
        />
        <StatTile
          icon={connection.status === "syncing" ? RefreshCw : Clock}
          label="Sync"
          value={connection.nextSyncAt ? `Next ${timeUntil(connection.nextSyncAt)}` : connection.lastSyncedAt ? "Up to date" : "Not synced"}
          secondary={connection.lastSyncedAt ? `Last synced ${timeAgo(connection.lastSyncedAt)}` : undefined}
          spin={connection.status === "syncing"}
        />
        <StatTile
          icon={Radar}
          label="Scan"
          value={scan.value}
          secondary={scan.secondary}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Connection details */}
        <Card as="section" className="lg:col-span-1">
          <div className="flex items-center justify-between gap-3">
            <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
              Connection details
            </h2>
            <StatusPill status={STATUS_PILL[connection.status]} label={STATUS_LABEL[connection.status]} />
          </div>

          <dl className="mt-4 divide-y divide-[var(--color-border)]">
            <DetailRow label="Provider">{SOURCE_TYPE_LABELS[connection.sourceType]}</DetailRow>
            {connection.connectionMethods.length > 0 && (
              <DetailRow label="Connected via">
                {connection.connectionMethods.map((m) => CONNECTION_METHOD_LABELS[m]).join(" + ")}
              </DetailRow>
            )}
            {connection.auth.orgOrOwner && (
              <DetailRow label="Organization">{connection.auth.orgOrOwner}</DetailRow>
            )}
            {connection.auth.instanceUrl && (
              <DetailRow label="Instance">{connection.auth.instanceUrl}</DetailRow>
            )}
            {scanners && <DetailRow label="Scanners">{scanners}</DetailRow>}
            <DetailRow label="Scan scope">
              {connection.scanScope === "all-except-excluded"
                ? `All except ${connection.excludedItems.length} excluded`
                : connection.scanScope === "selected"
                  ? `${connection.includedItems.length} selected`
                  : `All ${itemNoun}`}
            </DetailRow>
            <DetailRow label="Sync schedule">{SYNC_SCHEDULE_LABELS[connection.syncSchedule]}</DetailRow>
            <DetailRow label="Scan schedule">
              {connection.scanAutoEnabled
                ? connection.scanScheduleMode === "cron"
                  ? "Custom cron"
                  : SYNC_SCHEDULE_LABELS[connection.scanSchedulePreset]
                : "Manual only"}
            </DetailRow>
            {connection.createdAt && (
              <DetailRow label="Added">{timeAgo(connection.createdAt)}</DetailRow>
            )}
          </dl>
        </Card>

        {/* Discovered items */}
        <Card as="section" className="lg:col-span-2">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-base font-semibold capitalize text-[var(--color-text-primary)]">
              Discovered {itemNoun}
            </h2>
            {connection.discoveredItemCount != null && (
              <span className="shrink-0 rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5 text-xs font-medium tabular-nums text-[var(--color-text-secondary)]">
                {connection.discoveredItemCount.toLocaleString()}
              </span>
            )}
          </div>

          {items.length > 0 ? (
            <>
              <ul className="mt-3 grid gap-x-6 gap-y-1.5 sm:grid-cols-2">
                {items.slice(0, VISIBLE).map((item) => (
                  <li
                    key={item}
                    className="truncate font-mono text-xs text-[var(--color-text-secondary)]"
                    title={item}
                  >
                    {item}
                  </li>
                ))}
              </ul>
              {overflow > 0 && (
                <p className="mt-3 text-xs text-[var(--color-text-tertiary)]">
                  + {overflow.toLocaleString()} more
                </p>
              )}
            </>
          ) : (
            <p className="mt-3 text-sm text-[var(--color-text-secondary)]">
              {connection.discoveredItemCount
                ? `${connection.discoveredItemCount.toLocaleString()} ${itemNoun} discovered. Run a scan to surface findings.`
                : `No ${itemNoun} discovered yet. They'll appear after the next sync.`}
            </p>
          )}
        </Card>
      </div>
    </div>
  )
}
