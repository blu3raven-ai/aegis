"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import type {
  SourceConnection,
  SourceCategory,
  ScanScope,
  SyncSchedule,
} from "@/lib/shared/sources-types"
import {
  CATEGORY_LABELS,
  CATEGORY_ITEM_LABELS,
  SOURCE_TYPE_LABELS,
} from "@/lib/shared/sources-types"
import { getSourceConnection, updateSourceConnection } from "@/lib/client/sources-api"
import { ConnectionStatusBadge } from "./ConnectionStatusBadge"
import { ScopeConfigurator } from "./ScopeConfigurator"
import { SaveBar } from "@/app/(app)/settings/SaveBar"
import { SettingsCard } from "@/components/shared/SettingsCard"

// ─── Constants ────────────────────────────────────────────────────────────────

const SYNC_SCHEDULE_OPTIONS: { value: SyncSchedule; label: string }[] = [
  { value: "1h", label: "Every 1 hour" },
  { value: "3h", label: "Every 3 hours" },
  { value: "6h", label: "Every 6 hours" },
  { value: "12h", label: "Every 12 hours" },
  { value: "24h", label: "Every 24 hours" },
]

import { timeAgo } from "@/lib/shared/time-ago"
import { sectionHeadingClass } from "@/lib/shared/settings-styles"

// ─── Helpers ──────────────────────────────────────────────────────────────────

function maskToken(token: string | undefined): string {
  if (!token) return "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
  const last4 = token.slice(-4)
  return `\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022${last4}`
}

// ─── Settings row (matches Preferences page) ─────────────────────────────────

function SettingsRow({
  label,
  hint,
  children,
}: {
  label: string
  hint?: string
  children: React.ReactNode
}) {
  return (
    <div className="grid gap-4 border-b border-[var(--color-border)] px-5 py-[18px] last:border-b-0 md:grid-cols-[220px_1fr] md:gap-5">
      <div>
        <p className="text-sm font-medium text-[var(--color-text-primary)]">{label}</p>
        {hint && (
          <p className="mt-1 text-xs leading-relaxed text-[var(--color-text-secondary)]">{hint}</p>
        )}
      </div>
      <div className="flex items-start">{children}</div>
    </div>
  )
}

// ─── Props ────────────────────────────────────────────────────────────────────

interface ScopeConfigContentProps {
  connectionId: string
  category: SourceCategory
  canEdit: boolean
  basePath?: string
}

// ─── Component ────────────────────────────────────────────────────────────────

export function ScopeConfigContent({
  connectionId,
  category,
  canEdit,
  basePath,
}: ScopeConfigContentProps) {
  const categoryLabel = CATEGORY_LABELS[category]
  const itemLabel = CATEGORY_ITEM_LABELS[category]

  // ── Fetch state ──
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [loaded, setLoaded] = useState<SourceConnection | null>(null)

  // ── Editable state ──
  const [scanScope, setScanScope] = useState<ScanScope>("all")
  const [excludedItems, setExcludedItems] = useState<string[]>([])
  const [syncSchedule, setSyncSchedule] = useState<SyncSchedule>("6h")
  const [showTokenInput, setShowTokenInput] = useState(false)
  const [newToken, setNewToken] = useState("")

  // ── Save state ──
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  // ── Load on mount ──
  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setFetchError(null)

    getSourceConnection(connectionId).then((result) => {
      if (cancelled) return
      setLoading(false)
      if (!result.ok) {
        setFetchError(result.error)
        return
      }
      const conn = result.data.connection
      setLoaded(conn)
      setScanScope(conn.scanScope)
      setExcludedItems(conn.excludedItems)
      setSyncSchedule(conn.syncSchedule)
    })

    return () => {
      cancelled = true
    }
  }, [connectionId])

  // ── Dirty check ──
  const dirty =
    loaded !== null &&
    (scanScope !== loaded.scanScope ||
      syncSchedule !== loaded.syncSchedule ||
      showTokenInput ||
      JSON.stringify(excludedItems) !== JSON.stringify(loaded.excludedItems))

  // ── Save handler ──
  async function handleSave() {
    if (!loaded) return
    setSaving(true)
    setSaveError(null)

    const payload: Parameters<typeof updateSourceConnection>[1] = {
      scanScope,
      excludedItems,
      syncSchedule,
    }

    if (showTokenInput && newToken.trim()) {
      payload.auth = { ...loaded.auth, token: newToken.trim() }
    }

    const result = await updateSourceConnection(connectionId, payload)
    setSaving(false)

    if (!result.ok) {
      setSaveError(result.error)
      return
    }

    const conn = result.data.connection
    setLoaded(conn)
    setScanScope(conn.scanScope)
    setExcludedItems(conn.excludedItems)
    setSyncSchedule(conn.syncSchedule)
    setShowTokenInput(false)
    setNewToken("")
  }

  // ── Discard handler ──
  function handleDiscard() {
    if (!loaded) return
    setScanScope(loaded.scanScope)
    setExcludedItems(loaded.excludedItems)
    setSyncSchedule(loaded.syncSchedule)
    setShowTokenInput(false)
    setNewToken("")
    setSaveError(null)
  }

  // ─── Loading skeleton ──────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-4 w-40 animate-pulse rounded bg-[var(--color-surface-raised)]" />
        <div className="space-y-2">
          <div className="h-7 w-64 animate-pulse rounded bg-[var(--color-surface-raised)]" />
          <div className="h-4 w-48 animate-pulse rounded bg-[var(--color-surface-raised)]" />
        </div>
        <div className="h-48 animate-pulse rounded-xl bg-[var(--color-surface-raised)]" />
      </div>
    )
  }

  // ─── Error state ───────────────────────────────────────────────────────────

  if (fetchError) {
    return (
      <div className="space-y-6">
        <Link
          href={basePath || `/sources/${category}`}
          className="inline-flex items-center gap-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)] hover:underline"
        >
          <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="15 18 9 12 15 6" />
          </svg>
          Back to {categoryLabel}
        </Link>
        <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-500">
          {fetchError}
        </div>
      </div>
    )
  }

  if (!loaded) return null

  // Derived display values
  const sourceTypeLabel = SOURCE_TYPE_LABELS[loaded.sourceType]
  const orgOrOwner =
    loaded.auth.orgOrOwner ??
    loaded.auth.username ??
    loaded.auth.groupOrProject ??
    ""
  const orgFieldLabel =
    loaded.auth.orgOrOwner != null
      ? "Organization or owner"
      : loaded.auth.username != null
        ? "Username"
        : "Group / Project"

  // ─── Full form ─────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      {/* Back link */}
      <Link
        href={basePath || `/sources/${category}`}
        className="inline-flex items-center gap-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)]"
      >
        <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="15 18 9 12 15 6" />
        </svg>
        Back to {categoryLabel}
      </Link>

      {/* Connection header card */}
      <div className="flex items-center justify-between rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
        <div>
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            {loaded.name}
          </h2>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
            {sourceTypeLabel}
            {loaded.discoveredItemCount != null && (
              <> &middot; {loaded.discoveredItemCount.toLocaleString()} {itemLabel}</>
            )}
            {loaded.lastSyncedAt && (
              <> &middot; Last synced {timeAgo(loaded.lastSyncedAt)}</>
            )}
          </p>
        </div>
        <ConnectionStatusBadge status={loaded.status} />
      </div>

      {/* Scan Scope */}
      <SettingsCard eyebrow="Scan Scope" title="What to Scan" subtitle={`Choose which ${itemLabel} to include or exclude.`}>
        <ScopeConfigurator
          itemLabel={itemLabel}
          totalCount={loaded.discoveredItemCount ?? null}
          availableItems={loaded.discoveredItems ?? []}
          scanScope={scanScope}
          excludedItems={excludedItems}
          onScopeChange={setScanScope}
          onExcludedChange={setExcludedItems}
        />
      </SettingsCard>

      {/* Connection Settings */}
      <SettingsCard eyebrow="Connection" title="Authentication & Schedule" subtitle="Manage credentials and sync frequency.">
        <div className="overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)]">
          {/* Org / username — read-only */}
          {orgOrOwner && (
            <SettingsRow label={orgFieldLabel} hint="Set when the connection was created.">
              <input
                type="text"
                value={orgOrOwner}
                readOnly
                className="w-full max-w-sm rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none"
              />
            </SettingsRow>
          )}

          {/* Token */}
          <SettingsRow label="Access Token" hint="Used to authenticate API requests.">
            {showTokenInput ? (
              <div className="flex w-full max-w-sm items-center gap-2">
                <input
                  type="password"
                  value={newToken}
                  onChange={(e) => setNewToken(e.target.value)}
                  placeholder="Enter new token"
                  autoFocus
                  className="flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
                />
                <button
                  type="button"
                  onClick={() => {
                    setShowTokenInput(false)
                    setNewToken("")
                  }}
                  className="shrink-0 rounded-lg border border-[var(--color-border)] px-3 py-2 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)]"
                >
                  Cancel
                </button>
              </div>
            ) : (
              <div className="flex w-full max-w-sm items-center gap-2">
                <input
                  type="text"
                  value={maskToken(loaded.auth.token)}
                  readOnly
                  className="flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 font-mono text-sm text-[var(--color-text-secondary)] outline-none"
                />
                {canEdit && (
                  <button
                    type="button"
                    onClick={() => setShowTokenInput(true)}
                    className="shrink-0 rounded-lg border border-[var(--color-border)] px-3 py-2 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
                  >
                    Change
                  </button>
                )}
              </div>
            )}
          </SettingsRow>

          {/* Sync Schedule */}
          <SettingsRow label="Sync Schedule" hint="How often to re-discover items from this source.">
            <select
              value={syncSchedule}
              onChange={(e) => setSyncSchedule(e.target.value as SyncSchedule)}
              disabled={!canEdit}
              className="w-full max-w-sm rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none focus:ring-1 focus:ring-[var(--color-accent)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {SYNC_SCHEDULE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </SettingsRow>
        </div>
      </SettingsCard>

      {/* Save error */}
      {saveError && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-500">
          {saveError}
        </div>
      )}

      {/* SaveBar */}
      <SaveBar
        dirty={dirty && canEdit}
        saving={saving}
        onSave={handleSave}
        onDiscard={handleDiscard}
      />
    </div>
  )
}
