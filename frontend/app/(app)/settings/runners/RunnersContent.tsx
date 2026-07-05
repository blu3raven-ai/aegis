"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { useRouter } from "next/navigation"
import { handleRovingKeyDown } from "@/components/ui/roving"
import { fetchRunners, setRunnerMode } from "@/lib/client/settings/use-runners"
import { AddRunnerModal } from "./AddRunnerModal"
import { RemoteRunnerList } from "./RemoteRunnerList"
import type { Runner } from "./types"
import { useSSE } from "@/components/providers/SSEProvider"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { Skeleton } from "@/components/ui/Skeleton"
import { getSettings, saveToolSettings } from "@/lib/client/settings-api"
import { useHasPermission } from "@/lib/client/use-permission"

export function RunnersContent({ canEdit }: { canEdit: boolean }) {
  const router = useRouter()
  const [mode, setMode] = useState<"local" | "remote">("local")
  const [runners, setRunners] = useState<Runner[]>([])
  const [showAddModal, setShowAddModal] = useState(false)
  const [loading, setLoading] = useState(true)
  const [confirmModeSwitch, setConfirmModeSwitch] = useState<"local" | "remote" | null>(null)

  const loadRunners = useCallback(async () => {
    try {
      const data = await fetchRunners()
      setMode(data.mode as "local" | "remote" || "local")
      setRunners(data.runners || [])
    } catch { /* ignore */ }
    finally { setLoading(false) }
  }, [])

  useEffect(() => {
    void loadRunners()
  }, [loadRunners])

  useSSE("runner.status", () => {
    void loadRunners()
  })

  function requestModeChange(newMode: "local" | "remote") {
    if (newMode === mode) return
    if (mode === "remote" && runners.length > 0) {
      setConfirmModeSwitch(newMode)
      return
    }
    void commitModeChange(newMode)
  }

  async function commitModeChange(newMode: "local" | "remote") {
    setConfirmModeSwitch(null)
    setMode(newMode)
    await setRunnerMode(newMode)
  }

  if (loading) {
    return (
      <Skeleton className="h-40 rounded-lg" />
    )
  }

  const onlineCount = runners.filter((r) => r.status === "online").length
  const isEmpty = runners.length === 0

  return (
    <>
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)]">
        {/* Mode toggle row */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--color-border)] px-4 py-3">
          <div>
            <p className="text-sm font-medium text-[var(--color-text-primary)]">Execution mode</p>
            <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
              Where the scanners actually run.
            </p>
          </div>
          <SegmentedToggle
            options={[
              { value: "local", label: "Local" },
              { value: "remote", label: "Remote", badge: "Beta" },
            ]}
            value={mode}
            onChange={(next) => requestModeChange(next)}
            disabled={!canEdit}
          />
        </div>

        {/* Status row */}
        {mode === "local" ? (
          <LocalStatusBody online={onlineCount > 0} />
        ) : (
          <RemoteStatusBody
            runners={runners}
            isEmpty={isEmpty}
            onlineCount={onlineCount}
            canEdit={canEdit}
            onAddClick={() => setShowAddModal(true)}
            onRowClick={(r) => router.push(`/settings/runners/${r.id}`)}
            onChange={() => void loadRunners()}
          />
        )}
      </div>

      <ScanConcurrencyCard />

      {confirmModeSwitch && (
        <div className="rounded-lg border border-[var(--color-state-pending-border)] bg-[var(--color-state-pending-subtle)] p-4">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">Switch to Local mode?</p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            {runners.length} runner(s) are registered. Switching to Local mode means scans will run on this machine instead.
          </p>
          <div className="mt-3 flex gap-2">
            <Button variant="primary" size="sm" onClick={() => void commitModeChange(confirmModeSwitch)}>
              Switch to Local
            </Button>
            <Button variant="secondary" size="sm" onClick={() => setConfirmModeSwitch(null)}>
              Cancel
            </Button>
          </div>
        </div>
      )}

      <AddRunnerModal
        open={showAddModal}
        portalUrl={typeof window === "undefined" ? "" : window.location.origin}
        onClose={() => { setShowAddModal(false); void loadRunners() }}
      />
    </>
  )
}


// Scanners that accept a scan-concurrency knob (iac has none). Concurrency is
// how many workers each scan runs in parallel — a runner-load setting, so it
// lives here rather than duplicated on every scanner page. Stored per tool, but
// edited as one value applied across all of them.
const CONCURRENCY_TOOLS = [
  "dependencies_scanning",
  "container_scanning",
  "code_scanning",
  "secret_scanning",
] as const

function ScanConcurrencyCard() {
  // Concurrency writes tool config, which is manage_settings-gated — a plain
  // manage_runners user can see it but not edit.
  const { allowed: canEdit } = useHasPermission("manage_settings")
  const [value, setValue] = useState("")
  const [initial, setInitial] = useState("")
  const [enabledMap, setEnabledMap] = useState<Record<string, boolean>>({})
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const load = useCallback(async () => {
    const res = await getSettings()
    if (!res.ok) {
      setError(res.error)
      setLoading(false)
      return
    }
    const tools = res.data.tools
    const current = String(tools.dependencies_scanning.scanConcurrency ?? "4")
    setValue(current)
    setInitial(current)
    setEnabledMap(
      Object.fromEntries(CONCURRENCY_TOOLS.map((t) => [t, tools[t].enabled ?? false])),
    )
    setLoading(false)
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const dirty = value.trim() !== "" && value !== initial

  async function handleSave() {
    const n = Number(value)
    if (!Number.isInteger(n) || n <= 0) {
      setError("Enter a whole number greater than zero.")
      return
    }
    setSaving(true)
    setError(null)
    try {
      // Write every scanner. Pass each tool's current enablement through so a
      // concurrency change never enables (or trips the runner prereq on) a tool.
      for (const tool of CONCURRENCY_TOOLS) {
        const res = await saveToolSettings({
          tool,
          enabled: enabledMap[tool] ?? false,
          settings: { scanConcurrency: value },
        })
        if (!res.ok) {
          setError(res.error)
          return
        }
      }
      setInitial(value)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">Scan concurrency</p>
          <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
            Parallel workers each scan runs, applied to all scanners.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {saved && (
            <span className="text-xs text-[var(--color-status-ok)]">Saved</span>
          )}
          {dirty && canEdit && (
            <Button variant="primary" size="sm" onClick={() => void handleSave()} isLoading={saving}>
              Save
            </Button>
          )}
          <Input
            type="number"
            min={1}
            step={1}
            aria-label="Scan concurrency"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            disabled={!canEdit || loading || saving}
            className="w-20 tabular-nums"
          />
        </div>
      </div>
      {error && (
        <p className="mt-2 text-xs text-[var(--color-severity-critical-text)]">{error}</p>
      )}
    </div>
  )
}


interface SegmentedOption<T extends string> {
  value: T
  label: string
  badge?: string
}

interface SegmentedToggleProps<T extends string> {
  options: SegmentedOption<T>[]
  value: T
  onChange: (next: T) => void
  disabled?: boolean
}

function SegmentedToggle<T extends string>({
  options,
  value,
  onChange,
  disabled,
}: SegmentedToggleProps<T>) {
  // Mirrors the shared <SegmentedControl> primitive; kept local only because it
  // also carries a string badge the primitive doesn't yet support. Reuses the
  // same roving-tabindex keyboard handler so the radiogroup is operable.
  const btnRefs = useRef<(HTMLButtonElement | null)[]>([])
  return (
    <div
      role="radiogroup"
      aria-label="Execution mode"
      className="inline-flex rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface-2)] p-0.5"
    >
      {options.map((opt, i) => {
        const selected = opt.value === value
        return (
          <button
            key={opt.value}
            ref={(el) => { btnRefs.current[i] = el }}
            type="button"
            role="radio"
            aria-checked={selected}
            disabled={disabled}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(opt.value)}
            onKeyDown={(e) =>
              handleRovingKeyDown(e, {
                index: i,
                count: options.length,
                orientation: "horizontal",
                onMove: (n) => {
                  onChange(options[n].value)
                  btnRefs.current[n]?.focus()
                },
              })
            }
            className={`inline-flex items-center gap-1.5 rounded-[5px] px-3 py-1 text-xs font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
              selected
                ? "bg-[var(--color-accent)] text-[var(--color-accent-on)]"
                : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            {opt.label}
            {opt.badge && (
              <span
                className={`rounded-sm px-1 py-0 text-[9px] font-bold uppercase tracking-[0.12em] ${
                  selected
                    ? "bg-[var(--color-accent-on)]/20 text-[var(--color-accent-on)]"
                    : "bg-[var(--color-bg-hover)] text-[var(--color-text-tertiary)]"
                }`}
              >
                {opt.badge}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}


function LocalStatusBody({ online }: { online: boolean }) {
  return (
    <div className="px-4 py-3">
      <div className="flex items-center gap-2">
        <span
          aria-hidden="true"
          className={`h-2 w-2 rounded-full ${
            online ? "bg-[var(--color-status-ok)]" : "bg-[var(--color-text-tertiary)]"
          }`}
        />
        <span className="text-sm font-semibold text-[var(--color-text-primary)]">
          {online ? "Local runner online" : "Local runner not connected"}
        </span>
      </div>
      <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
        Scanners run as Docker containers on this machine. The runner registers
        automatically when its service starts and uses local CPU, memory, and
        storage.
      </p>
      {!online && (
        <pre className="mt-2 overflow-x-auto rounded-md border border-[var(--color-border)] bg-[var(--color-surface-2)] px-3 py-2 font-mono text-xs text-[var(--color-text-primary)]">
          $ docker compose up
        </pre>
      )}
    </div>
  )
}


interface RemoteStatusBodyProps {
  runners: Runner[]
  isEmpty: boolean
  onlineCount: number
  canEdit: boolean
  onAddClick: () => void
  onRowClick: (runner: Runner) => void
  onChange: () => void
}

function RemoteStatusBody({
  runners,
  isEmpty,
  onlineCount,
  canEdit,
  onAddClick,
  onRowClick,
  onChange,
}: RemoteStatusBodyProps) {
  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span
              aria-hidden="true"
              className={`h-2 w-2 rounded-full ${
                isEmpty
                  ? "bg-[var(--color-text-tertiary)]"
                  : onlineCount > 0
                    ? "bg-[var(--color-status-ok)]"
                    : "bg-[var(--color-state-pending)]"
              }`}
            />
            <span className="text-sm font-semibold text-[var(--color-text-primary)]">
              {isEmpty
                ? "No runners registered"
                : `${runners.length} runner${runners.length === 1 ? "" : "s"} · ${onlineCount} online`}
            </span>
          </div>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            Scanners run on separate machines you register. Runners are trusted
            with repository tokens and registry credentials — only register on
            machines you control.
          </p>
        </div>
        {canEdit && (
          <Button variant="primary" size="sm" onClick={onAddClick} className="shrink-0">
            Add Runner
          </Button>
        )}
      </div>

      {!isEmpty && (
        <RemoteRunnerList
          runners={runners}
          canApprove={canEdit}
          onRowClick={onRowClick}
          onChange={onChange}
        />
      )}
    </>
  )
}
