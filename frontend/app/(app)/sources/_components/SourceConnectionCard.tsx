"use client"

import { useState } from "react"
import type { SourceCategory, SourceConnection, SourceType } from "@/lib/shared/sources-types"
import { SOURCE_TYPE_LABELS, CATEGORY_ITEM_LABELS } from "@/lib/shared/sources-types"
import { syncSourceConnection, deleteSourceConnection } from "@/lib/client/sources-api"
import { timeAgo } from "@/lib/shared/time-ago"
import { Dialog } from "@/components/layout/Dialog"

const FOCUS_RING = "focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"

// ─── Status Badge ─────────────────────────────────────────────────────────────

const STATUS_CONFIG: Record<string, { dot: string; label: string; text: string }> = {
  connected: { dot: "bg-[var(--color-status-ok)]", label: "Connected", text: "text-[var(--color-status-ok)]" },
  syncing: { dot: "bg-[var(--color-severity-medium)] motion-safe:animate-pulse", label: "Syncing", text: "text-[var(--color-severity-medium)]" },
  error: { dot: "bg-[var(--color-severity-critical)]", label: "Error", text: "text-[var(--color-severity-critical)]" },
  disconnected: { dot: "bg-[var(--color-severity-critical)]", label: "Disconnected", text: "text-[var(--color-severity-critical)]" },
  "not-synced": { dot: "bg-[var(--color-text-tertiary)]", label: "Not Synced", text: "text-[var(--color-text-secondary)]" },
}

function StatusBadge({ status }: { status: SourceConnection["status"] }) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG["not-synced"]
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-0.5 text-[11px] font-semibold ${config.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${config.dot}`} aria-hidden="true" />
      {config.label}
    </span>
  )
}

// ─── Provider Logo ────────────────────────────────────────────────────────────

function ProviderLogo({ sourceType }: { sourceType: SourceType }) {
  const logoClass = "h-8 w-8 shrink-0"
  switch (sourceType) {
    case "github":
      return (
        <svg className={logoClass} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
          <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
        </svg>
      )
    case "gitlab":
      return (
        <svg className={logoClass} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
          <path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 01-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 014.82 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0118.6 2a.43.43 0 01.58 0 .42.42 0 01.11.18l2.44 7.51L23 13.45a.84.84 0 01-.35.94z" />
        </svg>
      )
    case "docker-hub":
      return (
        <svg className={logoClass} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
          <path d="M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.186.186 0 00-.185.186v1.887c0 .102.083.185.185.185zm-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.186.186 0 00-.185.185v1.888c0 .102.082.185.185.186zm0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.186.186 0 00-.185.185v1.887c0 .102.082.186.185.186zm-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.186.186 0 00-.185.185v1.887c0 .102.083.186.185.186zm-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.186.186 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.186.186.186zm5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.186.186 0 00-.185.186v1.887c0 .102.082.185.185.185zm-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.186v1.887c0 .102.083.185.185.185zm-2.964 0h2.119a.186.186 0 00.185-.185V9.006a.186.186 0 00-.185-.186H5.136a.186.186 0 00-.186.186v1.887c0 .102.084.185.186.185zm-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.186.186 0 00-.185.186v1.887c0 .102.083.185.185.185zM23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288z" />
        </svg>
      )
    case "ghcr":
      return (
        <svg className={logoClass} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
          <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
        </svg>
      )
    default:
      return <div className={`${logoClass} rounded-lg bg-[var(--color-surface-raised)]`} />
  }
}

// ─── Discovery Count Badge ────────────────────────────────────────────────────

function DiscoveryBadge({ count, itemLabel, status }: { count: number; itemLabel: string; status: SourceConnection["status"] }) {
  if (status === "syncing" && count === 0) return null
  if (status === "not-synced") {
    return (
      <span className="inline-flex items-center rounded-full bg-[var(--color-surface)] px-2 py-0.5 text-[11px] font-semibold text-[var(--color-text-secondary)]">
        Not synced
      </span>
    )
  }
  if (count === 0) return null
  return (
    <span className="inline-flex items-center rounded-full bg-[var(--color-accent)]/10 px-2 py-0.5 text-[11px] font-semibold tabular-nums text-[var(--color-accent)]">
      {count.toLocaleString()} {itemLabel}
    </span>
  )
}

// ─── Props ────────────────────────────────────────────────────────────────────

interface SourceConnectionCardProps {
  connection: SourceConnection
  category: SourceCategory
  onSync?: () => void
  onEdit?: () => void
  onDelete?: () => void
}

// ─── Component ────────────────────────────────────────────────────────────────

export function SourceConnectionCard({
  connection,
  category,
  onSync,
  onEdit,
  onDelete,
}: SourceConnectionCardProps) {
  const [isSyncing, setIsSyncing] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  const providerLabel = SOURCE_TYPE_LABELS[connection.sourceType]
  const itemLabel = CATEGORY_ITEM_LABELS[category]
  const discoveredItemCount = connection.discoveredItemCount ?? 0
  const syncedAgo = connection.lastSyncedAt ? timeAgo(connection.lastSyncedAt) : "never synced"
  const hasCustomName = connection.name && connection.name !== providerLabel
  const displayName = hasCustomName
    ? connection.name
    : connection.auth.orgOrOwner || connection.auth.username || connection.auth.groupOrProject || providerLabel

  async function handleSync(e: React.MouseEvent) {
    e.stopPropagation()
    setIsSyncing(true)
    await syncSourceConnection(connection.id)
    setIsSyncing(false)
    onSync?.()
  }

  async function handleDeleteConfirmed() {
    setIsDeleting(true)
    await deleteSourceConnection(connection.id)
    setIsDeleting(false)
    setShowDeleteConfirm(false)
    onDelete?.()
  }

  return (
    <>
      <Dialog
        open={showDeleteConfirm}
        onClose={() => setShowDeleteConfirm(false)}
        onConfirm={handleDeleteConfirmed}
        title={`Delete ${displayName}?`}
        description={`This will remove the connection and stop syncing ${discoveredItemCount > 0 ? `${discoveredItemCount.toLocaleString()} discovered ${itemLabel}` : itemLabel}. Scan history and findings will remain.`}
        confirmLabel={isDeleting ? "Deleting..." : "Delete Connection"}
        variant="danger"
      />

      <button
        type="button"
        onClick={() => onEdit?.()}
        className={`flex w-full items-center gap-4 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3 text-left transition-colors hover:border-[var(--color-accent)]/30 ${FOCUS_RING}`}
      >
        <div className="shrink-0 text-[var(--color-text-secondary)]">
          <ProviderLogo sourceType={connection.sourceType} />
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2.5">
            <p className="truncate text-sm font-semibold text-[var(--color-text-primary)]">
              {displayName}
            </p>
            <DiscoveryBadge count={discoveredItemCount} itemLabel={itemLabel} status={connection.status} />
          </div>
          <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
            {providerLabel} · {syncedAgo}
          </p>
          {connection.status === "error" && connection.statusMessage && (
            <p className="mt-1 text-xs text-[var(--color-severity-critical)]">{connection.statusMessage}</p>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-3">
          <button
            type="button"
            disabled={isSyncing}
            onClick={handleSync}
            className={`rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)] disabled:opacity-50 ${FOCUS_RING}`}
          >
            {isSyncing ? "Syncing\u2026" : "Sync Now"}
          </button>

          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); setShowDeleteConfirm(true) }}
            className={`rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-severity-critical)]/30 hover:text-[var(--color-severity-critical)] ${FOCUS_RING}`}
          >
            Delete
          </button>

          <StatusBadge status={connection.status} />
        </div>
      </button>
    </>
  )
}
