"use client"

import { useCallback, useEffect, useState } from "react"
import { fetchSbomHistory, type SbomHistoryEntry } from "@/lib/client/sbom-api"
import { relativeTime } from "@/lib/shared/relative-time"

interface SbomScanSelectorProps {
  label: string
  /** Ordered list of repo ids to display in the repo dropdown */
  repoIds: string[]
  selectedRepoId: string | null
  selectedHash: string | null
  onRepoChange: (repoId: string | null) => void
  onHashChange: (hash: string | null) => void
}

type HistoryState = "idle" | "loading" | "ok" | "error"

export function SbomScanSelector({
  label,
  repoIds,
  selectedRepoId,
  selectedHash,
  onRepoChange,
  onHashChange,
}: SbomScanSelectorProps) {
  const [history, setHistory] = useState<SbomHistoryEntry[]>([])
  const [historyState, setHistoryState] = useState<HistoryState>("idle")

  const loadHistory = useCallback(async (repoId: string) => {
    setHistoryState("loading")
    setHistory([])
    onHashChange(null)
    try {
      const entries = await fetchSbomHistory(repoId, 20)
      setHistory(entries)
      setHistoryState("ok")
      // Auto-select the most recent snapshot
      if (entries.length > 0) {
        onHashChange(entries[0].manifest_set_hash)
      }
    } catch {
      setHistoryState("error")
    }
  }, [onHashChange])

  useEffect(() => {
    if (selectedRepoId) {
      void loadHistory(selectedRepoId)
    } else {
      setHistory([])
      setHistoryState("idle")
      onHashChange(null)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedRepoId])

  return (
    <div className="flex flex-col gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        {label}
      </p>

      {/* Repo selector */}
      <div className="flex flex-col gap-1.5">
        <label className="text-[11px] text-[var(--color-text-secondary)]">Repository</label>
        <select
          value={selectedRepoId ?? ""}
          onChange={(e) => onRepoChange(e.target.value || null)}
          className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none transition-colors focus:border-[var(--color-accent)] focus:ring-1 focus:ring-[var(--color-accent)]"
        >
          <option value="">Select a repository…</option>
          {repoIds.map((id) => (
            <option key={id} value={id}>
              {id}
            </option>
          ))}
        </select>
      </div>

      {/* Snapshot selector — shown only when a repo is selected */}
      {selectedRepoId && (
        <div className="flex flex-col gap-1.5">
          <label className="text-[11px] text-[var(--color-text-secondary)]">Snapshot</label>
          {historyState === "loading" ? (
            <div className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-xs text-[var(--color-text-tertiary)]">
              <span className="h-3 w-3 shrink-0 rounded-full border-2 border-[var(--color-accent)] border-t-transparent motion-safe:animate-spin" />
              Loading snapshots…
            </div>
          ) : historyState === "error" ? (
            <p className="text-xs text-[var(--color-status-critical)]">
              Failed to load snapshots.{" "}
              <button
                type="button"
                onClick={() => selectedRepoId && void loadHistory(selectedRepoId)}
                className="underline hover:no-underline"
              >
                Retry
              </button>
            </p>
          ) : history.length === 0 ? (
            <p className="text-xs text-[var(--color-text-tertiary)]">
              No snapshots available for this repository.
            </p>
          ) : (
            <select
              value={selectedHash ?? ""}
              onChange={(e) => onHashChange(e.target.value || null)}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-[13px] text-[var(--color-text-primary)] font-[family-name:var(--font-jetbrains-mono)] outline-none transition-colors focus:border-[var(--color-accent)] focus:ring-1 focus:ring-[var(--color-accent)]"
            >
              <option value="">Select a snapshot…</option>
              {history.map((entry, idx) => (
                <option key={entry.manifest_set_hash} value={entry.manifest_set_hash}>
                  {entry.manifest_set_hash.slice(0, 16)}… — {relativeTime(entry.created_at)}
                  {idx === 0 ? " (latest)" : ""}
                </option>
              ))}
            </select>
          )}
        </div>
      )}
    </div>
  )
}
