"use client"

import { useState, useEffect, useCallback, useMemo } from "react"
import { CommandBar, type AttributeDef } from "@/components/shared/command-bar"
import { KpiCard } from "@/components/shared/KpiCard"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"
import { RepoSummaryRow } from "@/components/shared/repos/RepoSummaryRow"
import { EmptyReposState } from "@/components/shared/repos/EmptyReposState"
import { listRepos, type RepoSummary } from "@/lib/client/repos-api"

import { ReposDisplayOverflow, type ReposSortMode } from "./ReposDisplayOverflow"

type FilterMode = "all" | "critical" | "stale" | "missing-scanners"
type SortMode = ReposSortMode

const EXPECTED_SCANNERS = 4
const PER_PAGE = 25

const NEUTRAL = "text-[var(--color-text-primary)]"
const CRITICAL = "text-[var(--color-severity-critical)]"
const WARN = "text-[var(--color-severity-medium)]"
const OK = "text-[var(--color-state-fixed)]"

const REPOS_ATTRIBUTES: AttributeDef[] = [
  {
    key: "filter",
    label: "show",
    group: "Filter",
    description: "Critical · Stale · Missing scanners",
    type: "enum",
    options: [
      { value: "critical", label: "With critical" },
      { value: "stale", label: "Stale scans" },
      { value: "missing-scanners", label: "Missing scanners" },
    ],
  },
]

export interface RepositoriesPanelProps {
  /** Optional callback fired with the total repo count after each successful load. */
  onCountChange?: (count: number) => void
}

export function RepositoriesPanel({ onCountChange }: RepositoriesPanelProps = {}) {
  const [repos, setRepos] = useState<RepoSummary[]>([])
  const [search, setSearch] = useState<string>("")
  const [filter, setFilter] = useState<FilterMode>("all")
  const [sort, setSort] = useState<SortMode>("critical")
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadRepos = useCallback(async () => {
    setError(null)
    setLoading(true)
    try {
      const result = await listRepos({ limit: 200 })
      setRepos(result)
      onCountChange?.(result.length)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load repositories")
    } finally {
      setLoading(false)
    }
  }, [onCountChange])

  useEffect(() => {
    setPage(1)
    void loadRepos()
  }, [loadRepos])

  const stats = useMemo(() => {
    const withCritical = repos.filter((r) => r.findings_count_by_severity.critical > 0).length
    const stale = repos.filter((r) => r.coverage_status === "stale").length
    const never = repos.filter((r) => r.coverage_status === "never").length
    const totalCovered = repos.reduce((sum, r) => sum + r.scanners_with_coverage.length, 0)
    const avgCoveragePct = repos.length
      ? Math.round((totalCovered / (repos.length * EXPECTED_SCANNERS)) * 100)
      : 0
    return { withCritical, stale, never, avgCoveragePct }
  }, [repos])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return repos.filter((r) => {
      if (filter === "critical" && r.findings_count_by_severity.critical === 0) return false
      if (filter === "stale" && r.coverage_status === "fresh") return false
      if (filter === "missing-scanners" && r.scanners_with_coverage.length >= EXPECTED_SCANNERS) return false
      if (q && !r.repo.toLowerCase().includes(q) && !r.org.toLowerCase().includes(q)) return false
      return true
    })
  }, [repos, filter, search])

  const sorted = useMemo(() => {
    const copy = [...filtered]
    copy.sort((a, b) => {
      if (sort === "critical") {
        const diff = b.findings_count_by_severity.critical - a.findings_count_by_severity.critical
        if (diff !== 0) return diff
        return a.repo.localeCompare(b.repo)
      }
      if (sort === "last-scan") {
        const aTs = a.last_scanned_at ? Date.parse(a.last_scanned_at) : 0
        const bTs = b.last_scanned_at ? Date.parse(b.last_scanned_at) : 0
        return bTs - aTs
      }
      return a.repo.localeCompare(b.repo)
    })
    return copy
  }, [filtered, sort])

  const totalPages = Math.max(1, Math.ceil(sorted.length / PER_PAGE))
  const paged = sorted.slice((page - 1) * PER_PAGE, page * PER_PAGE)

  const isFiltered = search !== "" || filter !== "all"

  const values: Record<string, string | null> = {
    filter: filter === "all" ? null : filter,
  }

  const handleChange = (key: string, value: string | null) => {
    if (key === "filter") {
      setFilter((value ?? "all") as FilterMode)
      setPage(1)
    }
  }

  return (
    <>
      {error && (
        <div className="flex items-center justify-between gap-3 border-b border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-5 py-3">
          <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>
          <button
            type="button"
            onClick={() => void loadRepos()}
            className="shrink-0 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1 text-xs font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-4 sm:grid-cols-3 lg:grid-cols-4">
        <KpiCard
          label="With critical"
          value={loading && repos.length === 0 ? "—" : stats.withCritical.toLocaleString()}
          note={
            loading && repos.length === 0
              ? "Loading…"
              : stats.withCritical === 0
                ? "No critical findings"
                : `of ${repos.length.toLocaleString()} repos`
          }
          valueClass={stats.withCritical > 0 ? CRITICAL : OK}
        />
        <KpiCard
          label="Stale scans"
          value={loading && repos.length === 0 ? "—" : stats.stale.toLocaleString()}
          note={loading && repos.length === 0 ? "Loading…" : ">7d since last scan"}
          valueClass={stats.stale > 0 ? WARN : OK}
        />
        <KpiCard
          label="Never scanned"
          value={loading && repos.length === 0 ? "—" : stats.never.toLocaleString()}
          note={loading && repos.length === 0 ? "Loading…" : "Awaiting first scan"}
          valueClass={stats.never > 0 ? WARN : NEUTRAL}
        />
        <KpiCard
          label="Avg scanner coverage"
          value={loading && repos.length === 0 ? "—" : `${stats.avgCoveragePct}%`}
          note={loading && repos.length === 0 ? "Loading…" : `${EXPECTED_SCANNERS} scanners expected`}
          valueClass={
            stats.avgCoveragePct >= 75 ? OK : stats.avgCoveragePct >= 50 ? WARN : CRITICAL
          }
        />
      </div>

      <div className="border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-2.5">
        <CommandBar
          attributes={REPOS_ATTRIBUTES}
          values={values}
          onChange={handleChange}
          searchInput={search}
          onSearchInputChange={(v) => {
            setSearch(v)
            setPage(1)
          }}
          searchPlaceholder="Search repos…"
          displayOverflow={
            <ReposDisplayOverflow
              sort={sort}
              onSortChange={(next) => {
                setSort(next)
                setPage(1)
              }}
            />
          }
        />
      </div>

      <main className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-6 py-8">
      <div className="overflow-auto rounded-2xl border border-[var(--color-border)]">
        <table className="min-w-full divide-y divide-[var(--color-border)] text-sm">
          <thead className="bg-[var(--color-surface-raised)] text-left text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
            <tr>
              <th className="px-5 py-3">Repo</th>
              <th className="px-5 py-3">Severity</th>
              <th className="px-5 py-3">Coverage</th>
              <th className="px-5 py-3">Scanners</th>
              <th className="px-5 py-3">Last scan</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)]">
            {loading && repos.length === 0 ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} aria-hidden="true">
                  <td className="px-5 py-4"><div className="h-3 w-40 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" /></td>
                  <td className="px-5 py-4"><div className="h-3 w-28 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" /></td>
                  <td className="px-5 py-4"><div className="h-3 w-16 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" /></td>
                  <td className="px-5 py-4"><div className="h-3 w-24 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" /></td>
                  <td className="px-5 py-4"><div className="h-3 w-24 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" /></td>
                </tr>
              ))
            ) : paged.length > 0 ? (
              paged.map((repo) => (
                <RepoSummaryRow key={repo.repo_id} repo={repo} />
              ))
            ) : (
              <tr>
                <td colSpan={5} className="py-0">
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
          totalCount={sorted.length}
          perPage={PER_PAGE}
          onPageChange={setPage}
          onPerPageChange={() => {}}
          label="repos"
        />
      )}
      </main>
    </>
  )
}
