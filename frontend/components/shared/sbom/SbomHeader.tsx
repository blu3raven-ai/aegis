"use client"

import { relativeTime } from "@/lib/shared/relative-time"
import type { SbomFormat } from "@/lib/client/sbom-api"
import type { SbomHistoryEntry } from "@/lib/client/sbom-api"
import { SbomExportMenu } from "./SbomExportMenu"

export function SbomHeader({
  repoName,
  latestEntry,
  historyCount,
  onExport,
  onHistoryOpen,
  exportLoading = false,
}: {
  repoName: string
  latestEntry?: SbomHistoryEntry
  historyCount: number
  onExport: (format: SbomFormat, filename: string) => void
  onHistoryOpen: () => void
  exportLoading?: boolean
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-5 py-4">
      <div className="min-w-0">
        <h1 className="text-lg font-semibold tracking-tight text-[var(--color-text-primary)] truncate">
          SBOM — {repoName}
        </h1>

        {latestEntry ? (
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-[var(--color-text-secondary)]">
            <span className="flex items-center gap-1">
              <span className="text-[var(--color-text-tertiary)]">Current hash</span>
              <code className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-primary)]">
                {latestEntry.manifest_set_hash.slice(0, 12)}…
              </code>
            </span>
            <span className="text-[var(--color-text-tertiary)]">·</span>
            <span>Updated {relativeTime(latestEntry.created_at)}</span>
          </div>
        ) : (
          <p className="mt-1 text-xs text-[var(--color-text-tertiary)]">No SBOM generated yet</p>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-2">
        <button
          type="button"
          onClick={onHistoryOpen}
          className="flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          <svg
            className="h-3.5 w-3.5"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.5}
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
          </svg>
          History
          {historyCount > 0 && (
            <span className="rounded-full bg-[var(--color-surface-raised)] px-1.5 py-px font-mono text-2xs font-semibold text-[var(--color-text-secondary)]">
              {historyCount}
            </span>
          )}
        </button>

        <SbomExportMenu repoName={repoName} onExport={onExport} loading={exportLoading} />
      </div>
    </div>
  )
}
