"use client"

import { useEffect, useMemo, useState } from "react"
import { listFindingsSummary, type FindingsSummary } from "@/lib/client/findings-api"
import { listSavedViews, type SavedView } from "@/lib/client/saved-views-api"
import { SaveViewModal } from "@/components/shared/findings/SaveViewModal"
import { ManageViewsPanel } from "@/components/shared/findings/ManageViewsPanel"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

interface QueueItem {
  id: string
  label: string
  iconPath: string
  filters: Record<string, string>
  countKey?: keyof FindingsSummary
  tone?: "danger" | "neutral"
}

const MY_WORK_QUEUES: QueueItem[] = [
  {
    id: "all-open",
    label: "All open",
    iconPath: "M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V7M3 7l9 6 9-6",
    filters: { state: "open" },
    countKey: "open",
  },
  {
    id: "critical",
    label: "Critical open",
    iconPath: "M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z",
    filters: { state: "open", severity: "critical" },
    countKey: "critical",
    tone: "danger",
  },
  {
    id: "high",
    label: "High open",
    iconPath: "M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
    filters: { state: "open", severity: "high" },
    countKey: "high",
  },
]

const PRESET_QUEUES: QueueItem[] = [
  {
    id: "fixed",
    label: "Recently fixed",
    iconPath: "M4.5 12.75l6 6 9-13.5",
    filters: { state: "fixed" },
    countKey: "fixed_recent",
  },
  {
    id: "dismissed",
    label: "Dismissed",
    iconPath: "M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0",
    filters: { state: "dismissed" },
    countKey: "dismissed",
  },
]

// Active-queue highlighting compares the current board state (currentUrlState,
// passed down from FindingsBoardView) against each queue's filter recipe.
// "Exact" means every key the queue cares about matches, AND no other
// meaningful filter is set beyond its defaults.
function filtersMatch(state: Record<string, string>, target: Record<string, string>): boolean {
  for (const [key, value] of Object.entries(target)) {
    if (state[key] !== value) return false
  }
  return true
}

const MEANINGFUL_KEYS = ["state", "severity", "scanner", "repo", "q"] as const

function isExactMatch(state: Record<string, string>, target: Record<string, string>): boolean {
  if (!filtersMatch(state, target)) return false
  for (const key of MEANINGFUL_KEYS) {
    if (key in target) continue
    if (state[key] && state[key] !== "all") return false
  }
  return true
}

function formatCount(n: number | undefined): string | null {
  if (n === undefined) return null
  return n.toLocaleString()
}

function QueueIcon({ d }: { d: string }) {
  return (
    <svg
      className="h-3.5 w-3.5 shrink-0"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={d} />
    </svg>
  )
}

function QueueButton({
  item,
  active,
  count,
  onClick,
}: {
  item: QueueItem
  active: boolean
  count: string | null
  onClick: () => void
}) {
  const showDanger = item.tone === "danger" && count !== null && count !== "0"
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`relative flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-[13px] transition-colors ${
        active
          ? "bg-[var(--color-accent-subtle)] font-medium text-[var(--color-text-primary)]"
          : "text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
      }`}
    >
      {active && (
        <span
          aria-hidden="true"
          className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-full bg-[var(--color-accent)]"
        />
      )}
      <span className={active ? "text-[var(--color-accent)]" : ""}>
        <QueueIcon d={item.iconPath} />
      </span>
      <span className="flex-1 truncate">{item.label}</span>
      {count !== null && (
        <span
          className={`shrink-0 rounded-full px-1.5 py-0.5 text-[11px] font-medium tabular-nums ${
            showDanger
              ? "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]"
              : active
                ? "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                : "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]"
          }`}
        >
          {count}
        </span>
      )}
    </button>
  )
}

function QueueSection({
  label,
  items,
  summary,
  currentState,
  onSelect,
}: {
  label: string
  items: QueueItem[]
  summary: FindingsSummary | null
  currentState: Record<string, string>
  onSelect: (filters: Record<string, string>) => void
}) {
  return (
    <div className="px-2 pb-3">
      <div className="px-2.5 pb-1 pt-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
        {label}
      </div>
      <div className="flex flex-col gap-0.5">
        {items.map((item) => {
          const count = item.countKey && summary ? formatCount(summary[item.countKey] as number) : null
          return (
            <QueueButton
              key={item.id}
              item={item}
              active={isExactMatch(currentState, item.filters)}
              count={count}
              onClick={() => onSelect(item.filters)}
            />
          )
        })}
      </div>
    </div>
  )
}

function SavedViewButton({
  view,
  onApply,
}: {
  view: SavedView
  onApply: () => void
}) {
  return (
    <button
      type="button"
      onClick={onApply}
      className="flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-[13px] text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
      title={view.name}
    >
      <span aria-hidden="true" className="shrink-0 text-[var(--color-text-tertiary)]">
        {view.is_default ? (
          <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
            <path d="M12 2.5l2.95 5.98 6.6.96-4.78 4.66 1.13 6.57L12 17.77l-5.9 3.1 1.13-6.57L2.45 9.44l6.6-.96L12 2.5z" />
          </svg>
        ) : (
          <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M19 21V5a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2v16l7-4 7 4Z" />
          </svg>
        )}
      </span>
      <span className="flex-1 truncate">{view.name}</span>
    </button>
  )
}

function SavedViewsSection({
  applyView,
  currentUrlState,
  refreshSignal,
  onSavedViewCreated,
}: {
  applyView: (state: Record<string, string>) => void
  currentUrlState: Record<string, string>
  refreshSignal: number
  onSavedViewCreated: () => void
}) {
  const [views, setViews] = useState<SavedView[]>([])
  const [error, setError] = useState<string | null>(null)
  const [saveOpen, setSaveOpen] = useState(false)
  const [manageOpen, setManageOpen] = useState(false)

  useEffect(() => {
    let active = true
    listSavedViews("findings")
      .then((rows) => { if (active) { setViews(rows); setError(null) } })
      .catch((err) => { if (active) setError(err instanceof Error ? err.message : String(err)) })
    return () => { active = false }
  }, [refreshSignal])

  return (
    <div className="px-2 pb-3">
      <div className="px-2.5 pb-1 pt-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
        Saved views
      </div>

      {error && (
        <p className="px-2.5 py-1 text-2xs text-[var(--color-severity-critical)]">{error}</p>
      )}

      {!error && views.length === 0 && (
        <p className="px-2.5 py-1.5 text-xs text-[var(--color-text-tertiary)]">
          No saved views yet.
        </p>
      )}

      {views.length > 0 && (
        <div className="flex flex-col gap-0.5">
          {views.map((v) => (
            <SavedViewButton key={v.id} view={v} onApply={() => applyView(v.url_state)} />
          ))}
        </div>
      )}

      <div className="mt-1 flex items-center gap-1 px-2.5">
        <button
          type="button"
          onClick={() => setSaveOpen(true)}
          className="inline-flex items-center gap-1 rounded-md px-1.5 py-1 text-[11px] font-semibold text-[var(--color-accent)] whitespace-nowrap hover:bg-[var(--color-accent-subtle)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.4} strokeLinecap="round" aria-hidden="true">
            <path d="M12 5v14M5 12h14" />
          </svg>
          Save current view
        </button>
        {views.length > 0 && (
          <button
            type="button"
            onClick={() => setManageOpen(true)}
            aria-expanded={manageOpen}
            className="ml-auto rounded-md px-1.5 py-1 text-[11px] text-[var(--color-text-tertiary)] whitespace-nowrap hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
          >
            Manage
          </button>
        )}
      </div>

      <SaveViewModal
        open={saveOpen}
        onClose={() => setSaveOpen(false)}
        currentUrlState={currentUrlState}
        onSaved={() => {
          onSavedViewCreated()
        }}
      />

      <ManageViewsPanel
        open={manageOpen}
        onClose={() => setManageOpen(false)}
        variant="modal"
      />
    </div>
  )
}

export interface InboxQueueSidebarProps {
  applyView: (state: Record<string, string>) => void
  currentUrlState: Record<string, string>
  savedViewsRefreshSignal: number
  onSavedViewCreated: () => void
}

export function InboxQueueSidebar({
  applyView,
  currentUrlState,
  savedViewsRefreshSignal,
  onSavedViewCreated,
}: InboxQueueSidebarProps) {
  const [summary, setSummary] = useState<FindingsSummary | null>(null)

  // Stable key for refetching the summary when the board's filter state changes,
  // so per-queue counts reflect what's currently visible.
  const stateKey = useMemo(
    () => MEANINGFUL_KEYS.map((k) => currentUrlState[k] ?? "").join("|"),
    [currentUrlState],
  )

  useEffect(() => {
    let cancelled = false
    listFindingsSummary(ORG_ID)
      .then((data) => { if (!cancelled) setSummary(data) })
      .catch(() => { /* keep previous summary */ })
    return () => { cancelled = true }
  }, [stateKey])

  return (
    <aside
      aria-label="Inbox queues"
      className="hidden md:flex w-[220px] shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)] overflow-y-auto"
    >
      <QueueSection
        label="My work"
        items={MY_WORK_QUEUES}
        summary={summary}
        currentState={currentUrlState}
        onSelect={applyView}
      />
      <div className="mx-3 border-t border-[var(--color-border)]" />
      <QueueSection
        label="Presets"
        items={PRESET_QUEUES}
        summary={summary}
        currentState={currentUrlState}
        onSelect={applyView}
      />
      <div className="mx-3 border-t border-[var(--color-border)]" />
      <SavedViewsSection
        applyView={applyView}
        currentUrlState={currentUrlState}
        refreshSignal={savedViewsRefreshSignal}
        onSavedViewCreated={onSavedViewCreated}
      />
    </aside>
  )
}
