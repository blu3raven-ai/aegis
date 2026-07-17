"use client"

import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import { relativeTime } from "@/lib/shared/relative-time"
import type { SbomHistoryEntry } from "@/lib/client/sbom-api"
import { Button } from "@/components/ui/Button"
import { Skeleton } from "@/components/ui/Skeleton"

export function SbomHistoryDrawer({
  open,
  onClose,
  history,
  loading,
  atCap = false,
  selectedHash,
  onSelectVersion,
}: {
  open: boolean
  onClose: () => void
  history: SbomHistoryEntry[]
  loading: boolean
  /** True when the list hit its fetch cap — older snapshots may exist beyond it. */
  atCap?: boolean
  selectedHash: string | null
  onSelectVersion: (entry: SbomHistoryEntry) => void
}) {
  return (
    <FindingsDrawerShell open={open} onClose={onClose} label="SBOM version history">
      <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-3.5">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          Version History
        </h2>
        <Button
          variant="ghost"
          size="sm"
          iconOnly
          onClick={onClose}
          aria-label="Close history drawer"
          leadingIcon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M6 18 18 6M6 6l12 12" />
            </svg>
          }
        />

      </div>

      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex flex-col gap-2 p-5">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="flex flex-col gap-1.5 rounded-md border border-[var(--color-border)] p-4">
                <Skeleton className="h-3.5 w-40" />
                <Skeleton className="h-3 w-24" />
              </div>
            ))}
          </div>
        ) : history.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-3 px-5 py-16 text-center">
            <svg className="h-10 w-10 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
            </svg>
            <p className="text-sm text-[var(--color-text-secondary)]">No SBOM history found.</p>
          </div>
        ) : (
          <div className="flex flex-col gap-2 p-5">
            {history.map((entry, idx) => {
              const isSelected = selectedHash === entry.run_id
              const isLatest = idx === 0

              return (
                <button
                  key={entry.run_id}
                  type="button"
                  onClick={() => onSelectVersion(entry)}
                  aria-current={isSelected ? "true" : undefined}
                  className={`flex items-start gap-3 rounded-md border px-4 py-3.5 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] ${
                    isSelected
                      ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)]"
                      : "border-[var(--color-border)] hover:bg-[var(--color-surface-raised)]"
                  }`}
                >
                  <div className="mt-0.5 flex flex-col items-center gap-1">
                    <span
                      className={`h-2.5 w-2.5 rounded-full ${isSelected ? "bg-[var(--color-accent)]" : isLatest ? "bg-[var(--color-status-ok)]" : "bg-[var(--color-border-strong)]"}`}
                    />
                    {idx < history.length - 1 && (
                      <span className="h-6 w-px bg-[var(--color-border)]" />
                    )}
                  </div>

                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <code className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-primary)]">
                        {entry.run_id.slice(0, 16)}…
                      </code>
                      {isLatest && (
                        <span className="rounded-full bg-[var(--color-status-ok)]/10 px-2 py-px text-2xs font-semibold text-[var(--color-status-ok-text)]">
                          latest
                        </span>
                      )}
                    </div>
                    <p className="mt-0.5 text-[11px] text-[var(--color-text-secondary)]">
                      {relativeTime(entry.created_at)}
                    </p>
                  </div>

                  {isSelected && (
                    <svg className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M5 13l4 4L19 7" />
                    </svg>
                  )}
                </button>
              )
            })}
          </div>
        )}
      </div>

      <div className="border-t border-[var(--color-border)] px-5 py-3">
        <p className="text-[11px] text-[var(--color-text-tertiary)]">
          {atCap
            ? `Showing the latest ${history.length} snapshots`
            : `${history.length} snapshot${history.length !== 1 ? "s" : ""} stored`}
        </p>
      </div>
    </FindingsDrawerShell>
  )
}
