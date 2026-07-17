"use client"

import { useEffect, useMemo, useState } from "react"
import { StepLayout } from "@/components/shared/onboarding/StepLayout"
import { listRepos, type RepoSummary } from "@/lib/client/repos-api"
import { timeAgo } from "@/lib/shared/time-ago"

interface PickReposStepProps {
  onNext: (data: { repo_count: number; selected_repo_ids: string[] }) => void
  onBack: () => void
  onSkip: () => void
  saving?: boolean
}

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"
const SCAN_SECONDS_PER_REPO = 30

type RepoMeta = RepoSummary & {
  language?: string | null
  size_kb?: number | null
  pushed_at?: string | null
  is_private?: boolean | null
}

function formatSize(kb: number | null | undefined): string {
  if (kb == null) return "—"
  if (kb < 1024) return `${kb} KB`
  const mb = kb / 1024
  if (mb < 1024) return `${mb < 10 ? mb.toFixed(1) : Math.round(mb)} MB`
  const gb = mb / 1024
  return `${gb < 10 ? gb.toFixed(1) : Math.round(gb)} GB`
}

function formatScanDuration(seconds: number): string {
  if (seconds < 60) return `~${seconds}s scan`
  const minutes = Math.round(seconds / 60)
  return `~${minutes} min scan`
}

export function PickReposStep({ onNext, onBack, onSkip, saving = false }: PickReposStepProps) {
  const [repos, setRepos] = useState<RepoMeta[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [query, setQuery] = useState("")

  useEffect(() => {
    listRepos({ limit: 200 })
      .then((rows) => {
        setRepos(rows as RepoMeta[])
        setSelected(new Set(rows.map((r) => r.repo_id)))
      })
      .catch((e) => setError(String(e?.message ?? e)))
      .finally(() => setLoading(false))
  }, [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return repos
    return repos.filter((r) => r.repo_id.toLowerCase().includes(q) || r.repo.toLowerCase().includes(q))
  }, [repos, query])

  const totalKb = useMemo(() => {
    let kb = 0
    let hasAny = false
    for (const r of repos) {
      if (selected.has(r.repo_id) && r.size_kb != null) {
        kb += r.size_kb
        hasAny = true
      }
    }
    return hasAny ? kb : null
  }, [repos, selected])

  function toggle(repoId: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(repoId)) next.delete(repoId)
      else next.add(repoId)
      return next
    })
  }

  function selectAll() {
    setSelected(new Set(filtered.map((r) => r.repo_id)))
  }

  function deselectAll() {
    setSelected(new Set())
  }

  const selectedCount = selected.size
  const totalCount = repos.length
  const providerLabel = "GitHub"

  return (
    <StepLayout
      title="Choose repositories to scan"
      description="Aegis will only scan the repos you select here. You can add or remove repos anytime in Data → Repositories."
      onBack={onBack}
      onNext={loading ? undefined : () => onNext({ repo_count: selectedCount, selected_repo_ids: Array.from(selected) })}
      onSkip={onSkip}
      nextLabel="Start scanning"
      nextDisabled={loading || selectedCount === 0}
      loading={saving}
    >
      <div className="flex flex-col gap-4">
        {/* Account context row */}
        <div className="flex items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2">
          <div className="grid h-7 w-7 shrink-0 place-items-center rounded-md bg-[var(--color-surface-raised)] text-[var(--color-text-primary)]">
            <svg viewBox="0 0 24 24" fill="currentColor" className="h-4 w-4" aria-hidden="true">
              <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
            </svg>
          </div>
          <p className="min-w-0 truncate text-xs text-[var(--color-text-secondary)]">
            <span className="font-semibold text-[var(--color-text-primary)]">{providerLabel}</span>
            <span className="mx-1.5 text-[var(--color-text-tertiary)]">·</span>
            <span className="font-mono">{ORG_ID}</span>
            <span className="mx-1.5 text-[var(--color-text-tertiary)]">·</span>
            <span className="tabular-nums">
              {loading ? "discovering…" : `${totalCount} accessible ${totalCount === 1 ? "repository" : "repositories"}`}
            </span>
          </p>
        </div>

        {/* Search + bulk controls */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[180px] flex-1">
            <svg
              className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--color-text-tertiary)]"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={1.8}
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
            </svg>
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={loading ? "Loading repositories…" : `Search ${totalCount} ${totalCount === 1 ? "repository" : "repositories"}…`}
              disabled={loading}
              aria-label="Search repositories"
              className="h-8 w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] pl-8 pr-3 text-xs text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] disabled:opacity-60"
            />
          </div>
          <button
            type="button"
            onClick={selectAll}
            disabled={loading || filtered.length === 0}
            className="rounded-md px-2.5 py-1.5 text-xs font-medium text-[var(--color-accent)] transition-colors hover:bg-[var(--color-accent-subtle)] disabled:cursor-not-allowed disabled:opacity-50"
          >
            Select all
          </button>
          <button
            type="button"
            onClick={deselectAll}
            disabled={loading || selectedCount === 0}
            className="rounded-md px-2.5 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)] disabled:cursor-not-allowed disabled:opacity-50"
          >
            Deselect
          </button>
        </div>

        {/* Repo list */}
        <div className="max-h-96 overflow-y-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)]">
          {loading && (
            <p className="p-6 text-sm text-[var(--color-text-secondary)]">Discovering repositories…</p>
          )}
          {!loading && error && (
            <p className="p-6 text-sm text-[var(--color-text-secondary)]">
              Couldn&apos;t load repositories: {error}. You can continue and configure later in Sources.
            </p>
          )}
          {!loading && !error && filtered.length === 0 && (
            <p className="p-6 text-sm text-[var(--color-text-secondary)]">
              {repos.length === 0 ? "No repositories discovered yet." : "No repositories match your search."}
            </p>
          )}
          {!loading && !error && filtered.length > 0 && (
            <ul className="divide-y divide-[var(--color-border)]">
              {filtered.map((r) => {
                const isSelected = selected.has(r.repo_id)
                return (
                  <li key={r.repo_id}>
                    <label
                      className={`flex cursor-pointer items-center gap-3 px-4 py-3 transition-colors hover:bg-[var(--color-surface-raised)] ${
                        isSelected ? "bg-[var(--color-accent-subtle)]" : ""
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => toggle(r.repo_id)}
                        className="h-4 w-4 shrink-0 cursor-pointer accent-[var(--color-accent)]"
                        aria-label={`Select ${r.repo_id}`}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="truncate font-mono text-sm text-[var(--color-text-primary)]">{r.repo_id}</span>
                          {r.language && (
                            <span className="shrink-0 rounded border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-1.5 py-px text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                              {r.language}
                            </span>
                          )}
                          {r.is_private === true && (
                            <span className="shrink-0 rounded border border-[var(--color-border)] px-1.5 py-px text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                              Private
                            </span>
                          )}
                          {r.is_private === false && (
                            <span className="shrink-0 rounded border border-[var(--color-border)] px-1.5 py-px text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                              Public
                            </span>
                          )}
                        </div>
                      </div>
                      <span className="shrink-0 text-xs tabular-nums text-[var(--color-text-secondary)]">
                        {formatSize(r.size_kb)}
                      </span>
                      <span className="w-24 shrink-0 text-right text-xs text-[var(--color-text-secondary)]">
                        {r.pushed_at ? timeAgo(r.pushed_at) : "—"}
                      </span>
                    </label>
                  </li>
                )
              })}
            </ul>
          )}
        </div>

        {/* Summary footer */}
        {selectedCount > 0 && (
          <div className="flex items-center gap-3 rounded-lg border border-[var(--color-accent)]/25 bg-[var(--color-accent-subtle)] px-4 py-3">
            <div className="grid h-7 w-7 shrink-0 place-items-center rounded-md bg-[var(--color-accent)] text-white">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} className="h-3.5 w-3.5" aria-hidden="true">
                <path d="M5 12l5 5L20 7" />
              </svg>
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm text-[var(--color-text-primary)]">
                <strong className="font-semibold tabular-nums">
                  {selectedCount} of {totalCount}
                </strong>{" "}
                selected
                {totalKb != null && (
                  <>
                    <span className="mx-1.5 text-[var(--color-text-tertiary)]">·</span>
                    <span className="tabular-nums">~{formatSize(totalKb)}</span>
                  </>
                )}
                <span className="mx-1.5 text-[var(--color-text-tertiary)]">·</span>
                <span className="tabular-nums">{formatScanDuration(selectedCount * SCAN_SECONDS_PER_REPO)}</span>
              </p>
              <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
                Subsequent scans run on every push (incremental).
              </p>
            </div>
          </div>
        )}
      </div>
    </StepLayout>
  )
}
