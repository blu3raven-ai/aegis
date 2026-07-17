"use client"

import Link from "next/link"
import { useEffect, useMemo, useState } from "react"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Select } from "@/components/ui/Select"
import { KpiCard } from "@/components/shared/KpiCard"
import { CommandBar, type AttributeDef } from "@/components/shared/command-bar"
import { RepoCoverageBadge } from "@/components/shared/repos/RepoCoverageBadge"
import { listReposWithCount, type CoverageSummary, type FindingCounts, type RepoSummary } from "@/lib/client/sources-api"

// The repo list is fetched as a single capped page; when the estate exceeds it
// the UI surfaces "first N of M" rather than presenting the page as the total.
const REPO_LIMIT = 200
import { relativeTime } from "@/lib/shared/relative-time"
import { EmptySbomState } from "@/components/shared/sbom/EmptySbomState"
import { SbomEcosystemAnalyticsPanel } from "@/components/shared/sbom/SbomEcosystemAnalytics"

type CoverageFilter = "all" | "fresh" | "stale" | "never"
type SortMode = "coverage" | "last-scan" | "findings" | "name"

// Worst coverage first — the page exists to surface SBOM gaps.
const COVERAGE_RANK: Record<RepoSummary["coverage_status"], number> = {
  never: 0,
  stale: 1,
  fresh: 2,
}

// Mirror RepoCoverageBadge's labels + palette so a status reads the same
// across the KPI strip, the per-card badge, and the filter chips.
const COVERAGE_LABEL: Record<RepoSummary["coverage_status"], string> = {
  fresh: "Fresh",
  stale: "Stale",
  never: "Never scanned",
}

const OK = "text-[var(--color-status-ok-text)]"
const PENDING = "text-[var(--color-state-pending-text)]"
const NEUTRAL = "text-[var(--color-text-primary)]"

type Severity = keyof FindingCounts

// Highest-to-lowest so the first non-zero bucket is the worst present.
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"]

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
}

// Static literal class strings per severity — Tailwind v4's JIT only matches
// complete class names, so the severity must never be interpolated into the class.
const SEVERITY_PILL: Record<Severity, string> = {
  critical:
    "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]",
  high: "border-[var(--color-severity-high-border)] bg-[var(--color-severity-high-subtle)] text-[var(--color-severity-high-text)]",
  medium:
    "border-[var(--color-severity-medium-border)] bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium-text)]",
  low: "border-[var(--color-severity-low-border)] bg-[var(--color-severity-low-subtle)] text-[var(--color-severity-low-text)]",
}

function totalFindings(repo: RepoSummary): number {
  // Authoritative open-finding total (includes NULL/non-canonical severities the
  // four-bucket breakdown drops); the buckets still drive the worst-severity pill.
  return repo.open_finding_count
}

// The most severe bucket carrying at least one finding, or null when clean.
function worstSeverity(counts: FindingCounts): { severity: Severity; count: number } | null {
  for (const severity of SEVERITY_ORDER) {
    const count = counts[severity]
    if (count > 0) return { severity, count }
  }
  return null
}

function RepoCard({ repo }: { repo: RepoSummary }) {
  const findings = totalFindings(repo)
  const worst = worstSeverity(repo.findings_count_by_severity)
  const lastScanned = repo.last_scanned_at ? relativeTime(repo.last_scanned_at) : null

  const worstLabel = worst
    ? `, worst severity ${SEVERITY_LABEL[worst.severity]} (${worst.count.toLocaleString()})`
    : ""

  return (
    <Link
      href={`/sbom/${encodeURIComponent(repo.repo_id)}`}
      aria-label={`View SBOM for ${repo.repo} — ${COVERAGE_LABEL[repo.coverage_status]}, ${findings.toLocaleString()} findings${worstLabel}`}
      className="group flex flex-col gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4 shadow-[var(--shadow-card)] transition-colors hover:border-[var(--color-accent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 flex-col gap-1">
          <h2 className="truncate font-[family-name:var(--font-jetbrains-mono)] text-sm font-semibold text-[var(--color-text-primary)]">
            {repo.repo}
          </h2>
          <p className="text-xs text-[var(--color-text-secondary)]">{repo.org}</p>
        </div>

        <RepoCoverageBadge status={repo.coverage_status} />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1 text-xs">
        <span className="flex min-w-0 items-center gap-1.5 text-[var(--color-text-secondary)]">
          <svg className="h-3 w-3 shrink-0 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 0 1 0 3.75H5.625a1.875 1.875 0 0 1 0-3.75Z" />
          </svg>
          <strong className="font-semibold tabular-nums text-[var(--color-text-primary)]">
            {findings.toLocaleString()}
          </strong>{" "}
          findings
          {worst && (
            <span
              className={`ml-1 inline-flex shrink-0 items-center gap-1 rounded-full border px-2 py-0.5 text-2xs font-medium tabular-nums ${SEVERITY_PILL[worst.severity]}`}
            >
              {SEVERITY_LABEL[worst.severity]} {worst.count.toLocaleString()}
            </span>
          )}
        </span>
        {lastScanned && (
          <span className="shrink-0 text-[var(--color-text-secondary)]">Updated {lastScanned}</span>
        )}
      </div>
    </Link>
  )
}

export default function SbomRepositoriesPage() {
  const [repos, setRepos] = useState<RepoSummary[]>([])
  const [totalCount, setTotalCount] = useState<number | null>(null)
  const [coverageSummary, setCoverageSummary] = useState<CoverageSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [search, setSearch] = useState("")
  const [filter, setFilter] = useState<CoverageFilter>("all")
  const [sort, setSort] = useState<SortMode>("coverage")

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const { repos: result, totalCount: count, coverageSummary: cov } = await listReposWithCount({ limit: REPO_LIMIT })
      setRepos(result)
      setTotalCount(count)
      setCoverageSummary(cov)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load repositories")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const counts = useMemo(
    () => ({
      total: repos.length,
      fresh: repos.filter((r) => r.coverage_status === "fresh").length,
      stale: repos.filter((r) => r.coverage_status === "stale").length,
      never: repos.filter((r) => r.coverage_status === "never").length,
    }),
    [repos],
  )

  // KPI strip counts the FULL estate (server-computed), not just the fetched
  // page, so Fresh/Stale/Never stay correct past the page cap. Falls back to the
  // page-local counts before the first response lands.
  const kpi = coverageSummary ?? counts

  // True when the estate has more repos than the single page we fetched.
  const capped = totalCount != null && totalCount > repos.length

  // Repos matching the search box, before the coverage filter is applied.
  const searchMatched = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return repos
    return repos.filter(
      (r) => r.repo.toLowerCase().includes(q) || r.org.toLowerCase().includes(q),
    )
  }, [repos, search])

  const filtered = useMemo(
    () =>
      filter === "all"
        ? searchMatched
        : searchMatched.filter((r) => r.coverage_status === filter),
    [searchMatched, filter],
  )

  const sorted = useMemo(() => {
    const copy = [...filtered]
    copy.sort((a, b) => {
      if (sort === "coverage") {
        const d = COVERAGE_RANK[a.coverage_status] - COVERAGE_RANK[b.coverage_status]
        return d !== 0 ? d : a.repo.localeCompare(b.repo)
      }
      if (sort === "last-scan") {
        const at = a.last_scanned_at ? Date.parse(a.last_scanned_at) : 0
        const bt = b.last_scanned_at ? Date.parse(b.last_scanned_at) : 0
        return bt - at
      }
      if (sort === "findings") {
        const d = totalFindings(b) - totalFindings(a)
        return d !== 0 ? d : a.repo.localeCompare(b.repo)
      }
      return a.repo.localeCompare(b.repo)
    })
    return copy
  }, [filtered, sort])

  const isFiltered = search !== "" || filter !== "all"

  function resetFilters() {
    setSearch("")
    setFilter("all")
  }

  const repoAttributes: AttributeDef[] = [
    {
      key: "coverage",
      label: "coverage",
      group: "Coverage",
      description: "Fresh · Stale · Never scanned",
      type: "enum",
      options: [
        { value: "fresh", label: "Fresh" },
        { value: "stale", label: "Stale" },
        { value: "never", label: "Never scanned" },
      ],
    },
  ]

  return (
    <div className="space-y-5 px-6 py-6">
      {/* Coverage KPIs */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard
          label="Repositories"
          value={loading && repos.length === 0 ? "—" : kpi.total.toLocaleString()}
          note={loading && repos.length === 0 ? "Loading…" : "In coverage scope"}
          valueClass={NEUTRAL}
        />
        <KpiCard
          label="Fresh"
          value={loading && repos.length === 0 ? "—" : kpi.fresh.toLocaleString()}
          note={loading && repos.length === 0 ? "Loading…" : "Scanned recently"}
          valueClass={kpi.fresh > 0 ? OK : NEUTRAL}
        />
        <KpiCard
          label="Stale"
          value={loading && repos.length === 0 ? "—" : kpi.stale.toLocaleString()}
          note={loading && repos.length === 0 ? "Loading…" : "Scan is outdated"}
          valueClass={kpi.stale > 0 ? PENDING : NEUTRAL}
        />
        <KpiCard
          label="Never scanned"
          value={loading && repos.length === 0 ? "—" : kpi.never.toLocaleString()}
          note={loading && repos.length === 0 ? "Loading…" : "No SBOM yet"}
          valueClass={NEUTRAL}
        />
      </div>

      <p className="text-2xs text-[var(--color-text-secondary)]">
        Coverage = whether a dependency-scan SBOM exists; independent of finding counts, which other scanners also produce.
      </p>

      <SbomEcosystemAnalyticsPanel />

      {error && (
        <div
          role="alert"
          className="flex items-center justify-between gap-3 rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3"
        >
          <p className="text-sm text-[var(--color-severity-critical-text)]">{error}</p>
          <Button variant="secondary" size="sm" onClick={() => void load()}>
            Retry
          </Button>
        </div>
      )}

      {/* Faceted command bar — same search pattern as the Findings tab */}
      <CommandBar
        attributes={repoAttributes}
        values={{ coverage: filter === "all" ? null : filter }}
        onChange={(key, value) => {
          if (key === "coverage") setFilter((value ?? "all") as CoverageFilter)
        }}
        searchInput={search}
        onSearchInputChange={setSearch}
        searchPlaceholder="Search repositories…"
        displayOverflow={
          // Fixed-width wrapper: the Select primitive is `w-full`, so without a
          // bounded parent it would stretch and starve the flex-1 search box.
          <div className="w-52 shrink-0">
            <Select
              size="sm"
              value={sort}
              onChange={(e) => setSort(e.target.value as SortMode)}
              aria-label="Sort repositories"
            >
              <option value="coverage">Coverage gaps first</option>
              <option value="last-scan">Last scanned</option>
              <option value="findings">Most findings</option>
              <option value="name">Name</option>
            </Select>
          </div>
        }
      />

      {loading && repos.length === 0 ? (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5" aria-hidden="true">
          {Array.from({ length: 10 }).map((_, i) => (
            <Card key={i} padding="none" className="h-[100px] rounded-xl motion-safe:animate-pulse" />
          ))}
        </div>
      ) : !loading && !error && repos.length === 0 ? (
        <EmptySbomState />
      ) : repos.length === 0 ? (
        // Initial fetch failed with nothing loaded — the error banner stands alone.
        <></>
      ) : sorted.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-[var(--color-border)] py-16 text-center">
          <p className="text-sm text-[var(--color-text-secondary)]">
            No repositories match the current filters.
          </p>
          {isFiltered && (
            <Button variant="secondary" size="sm" onClick={resetFilters}>
              Clear filters
            </Button>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-xs text-[var(--color-text-secondary)] tabular-nums">
            {isFiltered
              ? capped
                ? // Only the first page was fetched, so a filter searches the loaded
                  // subset, not the estate — say so, or the count looks like the whole.
                  `${sorted.length.toLocaleString()} of ${counts.total.toLocaleString()} loaded · ${totalCount!.toLocaleString()} in estate`
                : `${sorted.length.toLocaleString()} of ${counts.total.toLocaleString()} repositories`
              : capped
                ? `Showing the first ${counts.total.toLocaleString()} of ${totalCount!.toLocaleString()} repositories`
                : `${counts.total.toLocaleString()} ${counts.total === 1 ? "repository" : "repositories"}`}
          </p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
            {sorted.map((r) => (
              <RepoCard key={r.repo_id} repo={r} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
