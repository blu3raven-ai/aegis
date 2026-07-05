"use client"

import { useState, useEffect, useCallback } from "react"
import { SearchInput } from "@/components/shared/SearchInput"
import { FilterTag } from "@/components/shared/FilterTag"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"
import { RepoSummaryRow } from "@/components/shared/repos/RepoSummaryRow"
import { EmptyReposState } from "@/components/shared/repos/EmptyReposState"
import { listRepos, type RepoSummary } from "@/lib/client/repos-api"

type FilterMode = "all" | "critical" | "stale"

const PER_PAGE = 25

export function RepositoriesPanel() {
  const [repos, setRepos] = useState<RepoSummary[]>([])
  const [search, setSearch] = useState("")
  const [filter, setFilter] = useState<FilterMode>("all")
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadRepos = useCallback(async () => {
    setError(null)
    setLoading(true)
    try {
      const result = await listRepos({
        has_critical: filter === "critical" ? true : undefined,
        since_days: filter === "stale" ? undefined : undefined,
        limit: 200,
      })
      setRepos(result)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load repositories")
    } finally {
      setLoading(false)
    }
  }, [filter])

  useEffect(() => {
    setPage(1)
    void loadRepos()
  }, [loadRepos])

  let visible = repos
  if (search) {
    const q = search.toLowerCase()
    visible = visible.filter((r) => r.repo.toLowerCase().includes(q) || r.org.toLowerCase().includes(q))
  }
  if (filter === "critical") {
    visible = visible.filter((r) => r.findings_count_by_severity.critical > 0)
  }
  if (filter === "stale") {
    visible = visible.filter((r) => r.coverage_status === "stale" || r.coverage_status === "never")
  }

  const totalPages = Math.max(1, Math.ceil(visible.length / PER_PAGE))
  const paged = visible.slice((page - 1) * PER_PAGE, page * PER_PAGE)

  const isFiltered = search !== "" || filter !== "all"

  return (
    <main className="mx-auto flex max-w-7xl flex-col gap-6 px-6 py-8">
      {error && (
        <div className="mb-4 flex items-center justify-between gap-3 rounded-xl border border-[var(--color-status-critical)]/30 bg-[var(--color-status-critical)]/5 px-4 py-3">
          <p className="text-[13px] text-[var(--color-status-critical)]">{error}</p>
          <button
            type="button"
            onClick={() => void loadRepos()}
            className="shrink-0 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1 text-[12px] font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex flex-wrap items-center gap-2">
          {(["all", "critical", "stale"] as FilterMode[]).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => { setFilter(f); setPage(1) }}
              className={`rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors ${
                filter === f
                  ? "border-[var(--color-accent)]/50 bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                  : "border-[var(--color-border)] bg-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              {f === "all" ? "All" : f === "critical" ? "Has critical" : "Stale scans"}
            </button>
          ))}
          {search && (
            <FilterTag label={`"${search}"`} onClear={() => { setSearch(""); setPage(1) }} />
          )}
        </div>

        <SearchInput
          value={search}
          onChange={(v) => { setSearch(v); setPage(1) }}
          placeholder="Search repos…"
        />
      </div>

      {loading && repos.length === 0 && (
        <div className="flex items-center justify-center py-16">
          <span className="h-6 w-6 rounded-full border-2 border-[var(--color-accent)] border-t-transparent motion-safe:animate-spin" />
        </div>
      )}

      <div className="overflow-auto rounded-2xl border border-[var(--color-border)]">
        <table className="min-w-full divide-y divide-[var(--color-border)] text-sm">
          <thead className="bg-[var(--color-surface-raised)] text-left text-xs uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            <tr>
              <th className="px-5 py-3">Repo</th>
              <th className="px-5 py-3">Coverage</th>
              <th className="px-5 py-3">Scanners</th>
              <th className="px-5 py-3">Findings</th>
              <th className="px-5 py-3">Chains</th>
              <th className="px-5 py-3">Last scan</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)]">
            {paged.length > 0 ? (
              paged.map((repo) => (
                <RepoSummaryRow key={repo.repo_id} repo={repo} />
              ))
            ) : (
              <tr>
                <td colSpan={6} className="py-0">
                  <EmptyReposState filtered={isFiltered} />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <PaginatedTableFooter
          page={page}
          totalPages={totalPages}
          totalCount={visible.length}
          perPage={PER_PAGE}
          onPageChange={setPage}
          onPerPageChange={() => {}}
          label="repos"
        />
      )}
    </main>
  )
}
