"use client"

import { useCallback, useEffect, useId, useState } from "react"
import { fetchSbomHistory, type SbomHistoryEntry } from "@/lib/client/sbom-api"
import { relativeTime } from "@/lib/shared/relative-time"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Select } from "@/components/ui/Select"

/** A repository choice: the asset id is the option value, the label is the
 * human-readable repo name shown to the user. */
export interface RepoOption {
  id: string
  label: string
}

interface SbomScanSelectorProps {
  label: string
  /** Ordered list of repos to display in the repo dropdown */
  repos: RepoOption[]
  selectedRepoId: string | null
  selectedHash: string | null
  onRepoChange?: (repoId: string | null) => void
  onHashChange: (hash: string | null) => void
  /** Whether the repo list is still loading — gates the repo Select's loading
   * feedback. Only meaningful when the repo dropdown is shown (not locked). */
  reposLoading?: boolean
  /** Hide the repo dropdown — the repository is controlled by a sibling side.
   * Used for the diff target so both sides always compare the same repo. */
  lockRepo?: boolean
}

type HistoryState = "idle" | "loading" | "ok" | "error"

export function SbomScanSelector({
  label,
  repos,
  selectedRepoId,
  selectedHash,
  onRepoChange,
  onHashChange,
  reposLoading = false,
  lockRepo = false,
}: SbomScanSelectorProps) {
  const [history, setHistory] = useState<SbomHistoryEntry[]>([])
  const [historyState, setHistoryState] = useState<HistoryState>("idle")
  // This component renders twice on the Compare page; useId() keeps the
  // label/control associations unique and stable across both instances.
  const repoSelectId = useId()
  const snapshotSelectId = useId()

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
        onHashChange(entries[0].run_id)
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
    <Card padding="none" className="flex flex-col gap-3 rounded-xl p-4">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        {label}
      </p>

      {/* Repo selector — hidden when the repo is locked to a sibling side */}
      {!lockRepo && (
        <div className="flex flex-col gap-1.5">
          <label htmlFor={repoSelectId} className="text-xs text-[var(--color-text-secondary)]">Repository</label>
          {reposLoading ? (
            <div className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-xs text-[var(--color-text-tertiary)]">
              <span className="h-3 w-3 shrink-0 rounded-full border-2 border-[var(--color-accent)] border-t-transparent motion-safe:animate-spin" />
              Loading repositories…
            </div>
          ) : (
            <Select
              id={repoSelectId}
              value={selectedRepoId ?? ""}
              onChange={(e) => onRepoChange?.(e.target.value || null)}
            >
              <option value="">Select a repository…</option>
              {repos.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.label}
                </option>
              ))}
            </Select>
          )}
        </div>
      )}

      {lockRepo && !selectedRepoId && (
        <p className="text-xs text-[var(--color-text-tertiary)]">
          Select a repository on the base side.
        </p>
      )}

      {/* Snapshot selector — shown only when a repo is selected */}
      {selectedRepoId && (
        <div className="flex flex-col gap-1.5">
          <label htmlFor={snapshotSelectId} className="text-xs text-[var(--color-text-secondary)]">Snapshot</label>
          {historyState === "loading" ? (
            <div className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 text-xs text-[var(--color-text-tertiary)]">
              <span className="h-3 w-3 shrink-0 rounded-full border-2 border-[var(--color-accent)] border-t-transparent motion-safe:animate-spin" />
              Loading snapshots…
            </div>
          ) : historyState === "error" ? (
            <p className="text-xs text-[var(--color-severity-critical-text)]">
              Failed to load snapshots.{" "}
              <Button
                variant="link"
                size="xs"
                onClick={() => selectedRepoId && void loadHistory(selectedRepoId)}
                className="underline hover:no-underline"
              >
                Retry
              </Button>
            </p>
          ) : history.length === 0 ? (
            <p className="text-xs text-[var(--color-text-tertiary)]">
              No snapshots available for this repository.
            </p>
          ) : (
            <Select
              id={snapshotSelectId}
              value={selectedHash ?? ""}
              onChange={(e) => onHashChange(e.target.value || null)}
              className="font-[family-name:var(--font-jetbrains-mono)]"
            >
              <option value="">Select a snapshot…</option>
              {history.map((entry, idx) => (
                <option key={entry.run_id} value={entry.run_id}>
                  {idx === 0 ? "Latest · " : ""}
                  {relativeTime(entry.created_at)} · {entry.run_id.slice(0, 8)}
                </option>
              ))}
            </Select>
          )}
        </div>
      )}
    </Card>
  )
}
