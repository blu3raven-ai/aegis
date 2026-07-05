"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import type {
  SourceConnection,
  SourceCategory,
  ScanScope,
  ScannerType,
  ScheduleMode,
  SyncSchedule,
} from "@/lib/shared/sources-types"
import {
  CATEGORY_LABELS,
  CATEGORY_ITEM_LABELS,
  CATEGORY_SCANNERS,
  SCANNER_LABELS,
  SCANNER_DESCRIPTIONS,
  SOURCE_TYPE_LABELS,
} from "@/lib/shared/sources-types"
import { getSourceConnection, updateSourceConnection } from "@/lib/client/source-connections-api"
import { ConnectionStatusBadge } from "./ConnectionStatusBadge"
import { ScopeConfigurator } from "./ScopeConfigurator"
import { useSaveBarSection } from "@/app/(app)/settings/save-bar/SaveBarProvider"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"
import { SettingsCard } from "@/components/shared/SettingsCard"


const SYNC_SCHEDULE_OPTIONS: { value: SyncSchedule; label: string }[] = [
  { value: "1h", label: "Every 1 hour" },
  { value: "3h", label: "Every 3 hours" },
  { value: "6h", label: "Every 6 hours" },
  { value: "12h", label: "Every 12 hours" },
  { value: "24h", label: "Every 24 hours" },
]

import { timeAgo } from "@/lib/shared/time-ago"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { sectionHeadingClass } from "@/lib/shared/settings-styles"


// Lightweight client-side check mirroring the server's 5-field cron validation —
// drives inline feedback only; the server is the source of truth on save.
function isValidCron(expr: string): boolean {
  const fields = expr.trim().split(/\s+/)
  if (fields.length !== 5) return false
  const bounds: [number, number][] = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 6]]
  return fields.every((field, i) => {
    const [lo, hi] = bounds[i]
    return field.split(",").every((part) => {
      if (part === "*") return true
      const [base, step] = part.split("/")
      if (step !== undefined && (!/^\d+$/.test(step) || Number(step) === 0)) return false
      if (base === "*") return true
      if (base.includes("-")) {
        const [a, b] = base.split("-")
        return /^\d+$/.test(a) && /^\d+$/.test(b) && lo <= +a && +a <= +b && +b <= hi
      }
      return /^\d+$/.test(base) && lo <= +base && +base <= hi
    })
  })
}

const SCHEDULE_MODE_OPTIONS: { id: ScheduleMode; label: string }[] = [
  { id: "preset", label: "Preset" },
  { id: "cron", label: "Custom (cron)" },
]


function ScheduleEditor({
  mode, preset, cron, onModeChange, onPresetChange, onCronChange, disabled,
}: {
  mode: ScheduleMode
  preset: SyncSchedule
  cron: string
  onModeChange: (m: ScheduleMode) => void
  onPresetChange: (p: SyncSchedule) => void
  onCronChange: (c: string) => void
  disabled?: boolean
}) {
  const cronInvalid = mode === "cron" && cron.trim().length > 0 && !isValidCron(cron)
  return (
    <div className="w-full max-w-sm space-y-2">
      <SegmentedControl
        options={SCHEDULE_MODE_OPTIONS}
        value={mode}
        onChange={(m) => !disabled && onModeChange(m)}
        ariaLabel="Schedule mode"
      />
      {mode === "preset" ? (
        <Select
          value={preset}
          onChange={(e) => onPresetChange(e.target.value as SyncSchedule)}
          disabled={disabled}
        >
          {SYNC_SCHEDULE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>{opt.label}</option>
          ))}
        </Select>
      ) : (
        <>
          <Input
            value={cron}
            onChange={(e) => onCronChange(e.target.value)}
            placeholder="0 2 * * *"
            disabled={disabled}
            invalid={cronInvalid}
            className="font-mono"
          />
          <p className={cronInvalid
            ? "text-xs text-[var(--color-severity-critical-text)]"
            : "text-xs text-[var(--color-text-tertiary)]"}>
            {cronInvalid
              ? "Enter a valid 5-field cron (minute hour day month weekday)."
              : "Format: minute hour day month weekday — e.g. 0 2 * * * (daily 2am)."}
          </p>
        </>
      )}
    </div>
  )
}


function maskToken(token: string | undefined): string {
  if (!token) return "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
  const last4 = token.slice(-4)
  return `\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022${last4}`
}


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


function sameScannerSet(a: ScannerType[], b: ScannerType[]): boolean {
  return a.length === b.length && [...a].sort().join(",") === [...b].sort().join(",")
}


function ScannerSelector({
  applicable,
  selected,
  onToggle,
  disabled,
}: {
  applicable: ScannerType[]
  selected: ScannerType[]
  onToggle: (scanner: ScannerType) => void
  disabled?: boolean
}) {
  return (
    <div className="overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)]">
      {applicable.map((scanner) => {
        const checked = selected.includes(scanner)
        // Always keep at least one scanner selected — block unchecking the last.
        const lockOff = checked && selected.length === 1
        return (
          <label
            key={scanner}
            className={`flex items-start gap-3 border-b border-[var(--color-border)] px-5 py-[18px] last:border-b-0 ${
              disabled || lockOff ? "cursor-default" : "cursor-pointer"
            }`}
          >
            <input
              type="checkbox"
              checked={checked}
              disabled={disabled || lockOff}
              onChange={() => onToggle(scanner)}
              className="mt-0.5 h-4 w-4 rounded border-[var(--color-border)] accent-[var(--color-accent)]"
            />
            <span className="min-w-0">
              <span className="block text-sm font-medium text-[var(--color-text-primary)]">
                {SCANNER_LABELS[scanner]}
              </span>
              <span className="mt-0.5 block text-xs leading-relaxed text-[var(--color-text-secondary)]">
                {SCANNER_DESCRIPTIONS[scanner]}
              </span>
            </span>
          </label>
        )
      })}
    </div>
  )
}


interface ScopeConfigContentProps {
  connectionId: string
  category: SourceCategory
  canEdit: boolean
  basePath?: string
  /** When rendered inside the source-detail Settings tab, the page already has
   *  its own header and tab nav — hide the back link and connection summary
   *  card so they aren't duplicated. */
  embedded?: boolean
}


export function ScopeConfigContent({
  connectionId,
  category,
  canEdit,
  basePath,
  embedded = false,
}: ScopeConfigContentProps) {
  const categoryLabel = CATEGORY_LABELS[category]
  const itemLabel = CATEGORY_ITEM_LABELS[category]
  const applicableScanners = CATEGORY_SCANNERS[category]
  // Scanner selection is only meaningful when a category runs more than one
  // scanner — single-scanner categories always run that one scanner.
  const showScannerSelect = applicableScanners.length > 1

  // ── Fetch state ──
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [loaded, setLoaded] = useState<SourceConnection | null>(null)

  // ── Editable state ──
  const [scanScope, setScanScope] = useState<ScanScope>("all")
  const [excludedItems, setExcludedItems] = useState<string[]>([])
  const [scanners, setScanners] = useState<ScannerType[]>(applicableScanners)
  const [syncSchedule, setSyncSchedule] = useState<SyncSchedule>("6h")
  const [syncScheduleMode, setSyncScheduleMode] = useState<ScheduleMode>("preset")
  const [syncScheduleCron, setSyncScheduleCron] = useState("")
  const [scanAutoEnabled, setScanAutoEnabled] = useState(false)
  const [scanScheduleMode, setScanScheduleMode] = useState<ScheduleMode>("preset")
  const [scanSchedulePreset, setScanSchedulePreset] = useState<SyncSchedule>("24h")
  const [scanScheduleCron, setScanScheduleCron] = useState("")
  const [showTokenInput, setShowTokenInput] = useState(false)
  const [newToken, setNewToken] = useState("")

  // ── Save state ──
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  // Reset all editable state from a connection record.
  function hydrate(conn: SourceConnection) {
    setScanScope(conn.scanScope)
    setExcludedItems(conn.excludedItems)
    // Empty stored selection means "all applicable" — reflect that as all checked.
    setScanners(conn.scanners.length ? conn.scanners : applicableScanners)
    setSyncSchedule(conn.syncSchedule)
    setSyncScheduleMode(conn.syncScheduleMode ?? "preset")
    setSyncScheduleCron(conn.syncScheduleCron ?? "")
    setScanAutoEnabled(conn.scanAutoEnabled ?? false)
    setScanScheduleMode(conn.scanScheduleMode ?? "preset")
    setScanSchedulePreset(conn.scanSchedulePreset ?? "24h")
    setScanScheduleCron(conn.scanScheduleCron ?? "")
    setShowTokenInput(false)
    setNewToken("")
  }

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
      hydrate(conn)
    })

    return () => {
      cancelled = true
    }
  }, [connectionId])

  // Effective stored scanners (empty list == all applicable).
  const loadedScanners =
    loaded && loaded.scanners.length ? loaded.scanners : applicableScanners

  function toggleScanner(scanner: ScannerType) {
    setScanners((prev) => {
      if (prev.includes(scanner)) {
        if (prev.length === 1) return prev // keep at least one selected
        return prev.filter((s) => s !== scanner)
      }
      // Re-insert in canonical category order.
      return applicableScanners.filter((s) => s === scanner || prev.includes(s))
    })
  }

  // ── Dirty check ──
  const dirty =
    loaded !== null &&
    ((showScannerSelect && !sameScannerSet(scanners, loadedScanners)) ||
      scanScope !== loaded.scanScope ||
      syncSchedule !== loaded.syncSchedule ||
      syncScheduleMode !== (loaded.syncScheduleMode ?? "preset") ||
      syncScheduleCron !== (loaded.syncScheduleCron ?? "") ||
      scanAutoEnabled !== (loaded.scanAutoEnabled ?? false) ||
      scanScheduleMode !== (loaded.scanScheduleMode ?? "preset") ||
      scanSchedulePreset !== (loaded.scanSchedulePreset ?? "24h") ||
      scanScheduleCron !== (loaded.scanScheduleCron ?? "") ||
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
      ...(showScannerSelect ? { scanners } : {}),
      syncSchedule,
      syncScheduleMode,
      ...(syncScheduleMode === "cron" ? { syncScheduleCron: syncScheduleCron.trim() } : {}),
      scanAutoEnabled,
      scanScheduleMode,
      scanSchedulePreset,
      ...(scanScheduleMode === "cron" ? { scanScheduleCron: scanScheduleCron.trim() } : {}),
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
    hydrate(conn)
  }

  // ── Discard handler ──
  function handleDiscard() {
    if (!loaded) return
    hydrate(loaded)
    setSaveError(null)
  }

  useSaveBarSection({
    id: `source-scope:${connectionId}`,
    dirty: dirty && canEdit,
    saving,
    error: saveError,
    onSave: handleSave,
    onDiscard: handleDiscard,
  })

  // ─── Loading skeleton ──────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-4 w-40" />
        <div className="space-y-2">
          <Skeleton className="h-7 w-64" />
          <Skeleton className="h-4 w-48" />
        </div>
        <Skeleton className="h-48 rounded-xl" />
      </div>
    )
  }

  // ─── Error state ───────────────────────────────────────────────────────────

  if (fetchError) {
    return (
      <div className="space-y-6">
        {!embedded && (
          <Link
            href={basePath || `/sources/${category}`}
            className="inline-flex items-center gap-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)] hover:underline"
          >
            <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="15 18 9 12 15 6" />
            </svg>
            Back to {categoryLabel}
          </Link>
        )}
        <div className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3 text-sm text-[var(--color-severity-critical-text)]">
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
      {!embedded && (
        <>
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
          <Card className="flex items-center justify-between rounded-xl shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
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
          </Card>
        </>
      )}

      {/* Scan Scope */}
      <SettingsCard eyebrow="Scan Scope" title="What to Scan" subtitle={`Choose which scanners to run and which ${itemLabel} to include.`}>
        {showScannerSelect && (
          <div className="mb-6 space-y-3">
            <div>
              <p className="text-sm font-medium text-[var(--color-text-primary)]">Scanners to run</p>
              <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
                Which scanners run on Scan Now and scheduled scans. At least one is required.
              </p>
            </div>
            <ScannerSelector
              applicable={applicableScanners}
              selected={scanners}
              onToggle={toggleScanner}
              disabled={!canEdit}
            />
          </div>
        )}

        {showScannerSelect && (
          <div className="mb-6 border-t border-[var(--color-border)]" />
        )}

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

      {/* Schedule */}
      <SettingsCard
        eyebrow="Schedule"
        title="Sync & Scan Cadence"
        subtitle="Re-discover items and automatically re-run scans on a preset interval or a custom cron."
      >
        <div className="overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)]">
          {/* Sync schedule */}
          <SettingsRow label="Sync schedule" hint={`How often to re-discover ${itemLabel} from this source.`}>
            <ScheduleEditor
              mode={syncScheduleMode}
              preset={syncSchedule}
              cron={syncScheduleCron}
              onModeChange={setSyncScheduleMode}
              onPresetChange={setSyncSchedule}
              onCronChange={setSyncScheduleCron}
              disabled={!canEdit}
            />
          </SettingsRow>

          {/* Auto-scan toggle */}
          <SettingsRow label="Automatic scans" hint="Re-run a full scan of this source on a schedule, like clicking Scan Now.">
            <label className="flex cursor-pointer items-center gap-2.5">
              <input
                type="checkbox"
                checked={scanAutoEnabled}
                onChange={(e) => setScanAutoEnabled(e.target.checked)}
                disabled={!canEdit}
                className="h-4 w-4 rounded border-[var(--color-border)] accent-[var(--color-accent)]"
              />
              <span className="text-sm text-[var(--color-text-primary)]">
                {scanAutoEnabled ? "Enabled" : "Disabled"}
              </span>
            </label>
          </SettingsRow>

          {/* Auto-scan schedule (only when enabled) */}
          {scanAutoEnabled && (
            <SettingsRow label="Scan schedule" hint="When automatic scans run.">
              <ScheduleEditor
                mode={scanScheduleMode}
                preset={scanSchedulePreset}
                cron={scanScheduleCron}
                onModeChange={setScanScheduleMode}
                onPresetChange={setScanSchedulePreset}
                onCronChange={setScanScheduleCron}
                disabled={!canEdit}
              />
            </SettingsRow>
          )}
        </div>
      </SettingsCard>

      {/* Connection Settings */}
      <SettingsCard eyebrow="Connection" title="Authentication" subtitle="Manage credentials for this source.">
        <div className="overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-raised)]">
          {/* Org / username — read-only */}
          {orgOrOwner && (
            <SettingsRow label={orgFieldLabel} hint="Set when the connection was created.">
              <Input
                type="text"
                value={orgOrOwner}
                readOnly
                className="max-w-sm"
              />
            </SettingsRow>
          )}

          {/* Token */}
          <SettingsRow label="Access Token" hint="Used to authenticate API requests.">
            {showTokenInput ? (
              <div className="flex w-full max-w-sm items-center gap-2">
                <Input
                  type="password"
                  value={newToken}
                  onChange={(e) => setNewToken(e.target.value)}
                  placeholder="Enter new token"
                  autoFocus
                  className="flex-1"
                />
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    setShowTokenInput(false)
                    setNewToken("")
                  }}
                  className="shrink-0"
                >
                  Cancel
                </Button>
              </div>
            ) : (
              <div className="flex w-full max-w-sm items-center gap-2">
                <Input
                  type="text"
                  value={maskToken(loaded.auth.token)}
                  readOnly
                  className="flex-1 font-mono"
                />
                {canEdit && (
                  <Button variant="secondary" size="sm" onClick={() => setShowTokenInput(true)} className="shrink-0">
                    Change
                  </Button>
                )}
              </div>
            )}
          </SettingsRow>
        </div>
      </SettingsCard>

      {/* Save error */}
      {saveError && (
        <div className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3 text-sm text-[var(--color-severity-critical-text)]">
          {saveError}
        </div>
      )}
    </div>
  )
}
