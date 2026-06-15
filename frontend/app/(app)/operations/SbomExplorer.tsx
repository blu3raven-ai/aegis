"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { gqlQuery } from "@/lib/client/graphql-client"
import { useLicense } from "@/lib/client/license/client"
import { timeAgo } from "@/lib/shared/time-ago"
import { Button } from "@/components/ui/Button"
import { Input } from "@/components/ui/Input"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { Select } from "@/components/ui/Select"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import { Textarea } from "@/components/ui/Textarea"

// ---------------------------------------------------------------------------
// GraphQL queries
// ---------------------------------------------------------------------------

const SBOM_SEARCH_QUERY = `
  query SbomSearch(
    $search: String, $ecosystems: [String!], $source: String,
    $repos: [String!], $versionOp: String, $versionValue: String,
    $versionValueEnd: String, $filterLogic: String, $page: Int, $perPage: Int
  ) {
    sbomSearch(
      search: $search, ecosystems: $ecosystems, source: $source,
      repos: $repos, versionOp: $versionOp, versionValue: $versionValue,
      versionValueEnd: $versionValueEnd, filterLogic: $filterLogic, page: $page, perPage: $perPage
    ) {
      items {
        name version ecosystem purl repo org sourceTool scannedAt
      }
      total page perPage totalPages
    }
  }
`

const SBOM_FILTER_OPTIONS_QUERY = `
  query SbomFilterOptions {
    sbomFilterOptions { ecosystems repositories sources }
  }
`

const SBOM_CROSS_REFERENCES_QUERY = `
  query SbomCrossReferences($purl: String!) {
    sbomCrossReferences(purl: $purl) {
      repo org version sourceTool scannedAt
    }
  }
`

const SBOM_BULK_LOOKUP_QUERY = `
  query SbomBulkLookup($queries: [String!]!) {
    sbomBulkLookup(queries: $queries) {
      query found name version ecosystem purl repos
    }
  }
`

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SbomComponent {
  name: string; version: string; ecosystem: string; purl: string
  repo: string; org: string; sourceTool: string | null; scannedAt: string
}

interface SbomSearchResult {
  sbomSearch: {
    items: SbomComponent[]; total: number; page: number
    perPage: number; totalPages: number
  }
}

interface SbomFilterResult {
  sbomFilterOptions: { ecosystems: string[]; repositories: string[]; sources: string[] }
}

interface CrossRef {
  repo: string; org: string; version: string
  sourceTool: string | null; scannedAt: string
}

interface BulkMatch {
  query: string; found: boolean; name: string; version: string
  ecosystem: string; purl: string; repos: string[]
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ECOSYSTEM_COLORS: Record<string, string> = {
  npm: "bg-red-500/10 text-red-500",
  pypi: "bg-blue-500/10 text-[var(--color-accent)]",
  maven: "bg-orange-500/10 text-orange-500",
  golang: "bg-cyan-500/10 text-cyan-500",
  gem: "bg-pink-500/10 text-pink-500",
  nuget: "bg-[var(--color-argus-subtle)] text-[var(--color-argus)]",
  cargo: "bg-amber-500/10 text-amber-600",
  composer: "bg-indigo-500/10 text-indigo-500",
  hackage: "bg-violet-500/10 text-violet-500",
  hex: "bg-fuchsia-500/10 text-fuchsia-500",
  pub: "bg-sky-500/10 text-sky-500",
  cocoapods: "bg-rose-500/10 text-rose-500",
  swift: "bg-orange-500/10 text-orange-600",
  apk: "bg-teal-500/10 text-teal-500",
  deb: "bg-[var(--color-state-fixed-subtle)] text-[var(--color-state-fixed)]",
  rpm: "bg-yellow-500/10 text-yellow-600",
  "github-actions": "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]",
}

// ---------------------------------------------------------------------------
// Manifest parser — extracts package names from common formats
// ---------------------------------------------------------------------------

function parseManifestInput(raw: string): string[] {
  const trimmed = raw.trim()
  if (!trimmed) return []

  // Try JSON (package.json, package-lock.json, composer.json)
  if (trimmed.startsWith("{")) {
    try {
      const json = JSON.parse(trimmed)
      const names = new Set<string>()
      for (const key of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "require", "require-dev"]) {
        if (json[key] && typeof json[key] === "object") {
          for (const name of Object.keys(json[key])) names.add(name)
        }
      }
      if (names.size) return [...names]
    } catch {}
  }

  const lines = trimmed.split("\n").map((l) => l.trim()).filter(Boolean)

  // Detect format from line patterns
  const parsed: string[] = []
  for (const line of lines) {
    // Skip comments and section headers
    if (line.startsWith("#") || line.startsWith("//") || line.startsWith("[") || line.startsWith("--")) continue

    // requirements.txt: package==1.0, package>=1.0, package~=1.0, package!=1.0
    const pyMatch = line.match(/^([a-zA-Z0-9_.-]+)\s*([=<>!~]+.*)$/)
    if (pyMatch) { parsed.push(pyMatch[1]); continue }

    // go.mod: module/path v1.2.3
    const goMatch = line.match(/^\s*([a-zA-Z0-9_./-]+)\s+v[\d.]+/)
    if (goMatch) { parsed.push(goMatch[1]); continue }

    // Gemfile: gem 'name', '~> 1.0'
    const gemMatch = line.match(/^\s*gem\s+['"]([^'"]+)['"]/)
    if (gemMatch) { parsed.push(gemMatch[1]); continue }

    // Cargo.toml: name = "version" or name = { version = "..." }
    const cargoMatch = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*["'{]/)
    if (cargoMatch && !["name", "version", "edition", "authors", "description", "license", "repository", "readme", "keywords", "categories", "rust-version", "build", "workspace", "members", "exclude", "include", "publish", "default-run"].includes(cargoMatch[1])) {
      parsed.push(cargoMatch[1]); continue
    }

    // Maven/Gradle: group:artifact:version
    const mavenMatch = line.match(/^[\s'"]*([a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+)(?::[\d.]+)?/)
    if (mavenMatch && line.includes(":")) { parsed.push(mavenMatch[1]); continue }

    // PURL: pkg:ecosystem/name@version
    if (line.startsWith("pkg:")) { parsed.push(line.split("@")[0]); continue }

    // Plain package name (alphanumeric, dots, hyphens, underscores, slashes)
    const plainMatch = line.match(/^([a-zA-Z0-9@_./-]+)/)
    if (plainMatch) { parsed.push(plainMatch[1]); continue }
  }

  return [...new Set(parsed)]
}

type VersionOp = "" | "eq" | "gte" | "lte" | "range"
type FilterLogic = "and" | "or"
type ViewMode = "search" | "bulk"

// ---------------------------------------------------------------------------
// Small components
// ---------------------------------------------------------------------------

function EcosystemBadge({ ecosystem }: { ecosystem: string }) {
  const colors = ECOSYSTEM_COLORS[ecosystem] ?? "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
  return <span className={`inline-flex rounded-full px-2 py-0.5 text-2xs font-semibold ${colors}`}>{ecosystem}</span>
}

function SourceBadge({ sourceTool }: { sourceTool: string | null }) {
  const label = sourceTool ? "Dependencies" : "Container"
  const colors = sourceTool
    ? "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
    : "bg-[var(--color-argus-subtle)] text-[var(--color-argus)]"
  return <span className={`inline-flex rounded-full px-2 py-0.5 text-2xs font-semibold ${colors}`}>{label}</span>
}

function MultiSelect({
  label,
  options,
  selected,
  onChange,
}: {
  label: string
  options: string[]
  selected: string[]
  onChange: (v: string[]) => void
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener("mousedown", handleClick)
    return () => document.removeEventListener("mousedown", handleClick)
  }, [])

  function toggle(v: string) {
    onChange(selected.includes(v) ? selected.filter((s) => s !== v) : [...selected, v])
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="h-10 flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 text-sm text-[var(--color-text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
      >
        <span className={selected.length ? "" : "text-[var(--color-text-tertiary)]"}>
          {selected.length ? `${selected.length} ${label.toLowerCase()}` : `All ${label.toLowerCase()}`}
        </span>
        <svg className={`h-3.5 w-3.5 text-[var(--color-text-tertiary)] transition-transform ${open ? "rotate-180" : ""}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>

      {open && (
        <div className="absolute top-full left-0 z-40 mt-1 max-h-60 min-w-[180px] overflow-y-auto rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-1 shadow-lg">
          {options.length === 0 && (
            <p className="px-3 py-2 text-xs text-[var(--color-text-tertiary)]">None available</p>
          )}
          {options.map((opt) => (
            <button
              key={opt}
              type="button"
              onClick={() => toggle(opt)}
              className="flex w-full items-center gap-2 rounded-lg px-3 py-1.5 text-left text-sm transition-colors hover:bg-[var(--color-surface-raised)]"
            >
              <span className={`flex h-4 w-4 shrink-0 items-center justify-center rounded border ${selected.includes(opt) ? "border-[var(--color-accent)] bg-[var(--color-accent)]" : "border-[var(--color-border)]"}`}>
                {selected.includes(opt) && (
                  <svg className="h-3 w-3 text-[var(--color-accent-on)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={3} strokeLinecap="round" strokeLinejoin="round">
                    <path d="M5 13l4 4L19 7" />
                  </svg>
                )}
              </span>
              <span className="text-[var(--color-text-primary)]">{opt}</span>
            </button>
          ))}
          {selected.length > 0 && (
            <button
              type="button"
              onClick={() => onChange([])}
              className="mt-1 w-full rounded-lg px-3 py-1.5 text-left text-xs font-medium text-[var(--color-accent)] hover:bg-[var(--color-surface-raised)]"
            >
              Clear selection
            </button>
          )}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function SbomExplorer() {
  const { tier } = useLicense()
  const isEnterprise = tier === "enterprise"

  const [viewMode, setViewMode] = useState<ViewMode>("search")

  // Search filters
  const [search, setSearch] = useState("")
  const [debouncedSearch, setDebouncedSearch] = useState("")
  const [ecosystems, setEcosystems] = useState<string[]>([])
  const [source, setSource] = useState("")
  const [repos, setRepos] = useState<string[]>([])
  const [versionOp, setVersionOp] = useState<VersionOp>("")
  const [versionValue, setVersionValue] = useState("")
  const [versionValueEnd, setVersionValueEnd] = useState("")
  const [filterLogic, setFilterLogic] = useState<FilterLogic>("and")
  const [page, setPage] = useState(1)
  const perPage = 50

  const [data, setData] = useState<SbomSearchResult["sbomSearch"] | null>(null)
  const [filters, setFilters] = useState<SbomFilterResult["sbomFilterOptions"] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [expandedPurl, setExpandedPurl] = useState<string | null>(null)
  const [crossRefs, setCrossRefs] = useState<CrossRef[]>([])
  const [crossRefsLoading, setCrossRefsLoading] = useState(false)

  // Bulk lookup
  const [bulkInput, setBulkInput] = useState("")
  const [bulkResults, setBulkResults] = useState<BulkMatch[] | null>(null)
  const [bulkLoading, setBulkLoading] = useState(false)
  const [bulkError, setBulkError] = useState<string | null>(null)

  const searchInputRef = useRef<HTMLInputElement>(null)

  // Debounce search
  useEffect(() => {
    const t = setTimeout(() => { setDebouncedSearch(search); setPage(1) }, 300)
    return () => clearTimeout(t)
  }, [search])

  // Load filter options
  useEffect(() => {
    gqlQuery<SbomFilterResult>(SBOM_FILTER_OPTIONS_QUERY)
      .then((r) => setFilters(r.sbomFilterOptions))
      .catch(() => {})
  }, [])

  // Main search
  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await gqlQuery<SbomSearchResult>(SBOM_SEARCH_QUERY, {
        search: debouncedSearch || null,
        ecosystems: ecosystems.length ? ecosystems : null,
        source: source || null,
        repos: repos.length ? repos : null,
        versionOp: versionOp || null,
        versionValue: versionValue || null,
        versionValueEnd: versionValueEnd || null,
        filterLogic: filterLogic,
        page,
        perPage,
      })
      setData(result.sbomSearch)
    } catch (e: any) {
      setError(e.message || "Failed to load SBOM data")
    } finally {
      setLoading(false)
    }
  }, [debouncedSearch, ecosystems, source, repos, versionOp, versionValue, versionValueEnd, filterLogic, page, perPage])

  useEffect(() => { fetchData() }, [fetchData])

  // Cross-reference expand
  async function toggleCrossRef(purl: string) {
    if (expandedPurl === purl) { setExpandedPurl(null); return }
    setExpandedPurl(purl)
    setCrossRefsLoading(true)
    try {
      const result = await gqlQuery<{ sbomCrossReferences: CrossRef[] }>(SBOM_CROSS_REFERENCES_QUERY, { purl })
      setCrossRefs(result.sbomCrossReferences)
    } catch { setCrossRefs([]) }
    finally { setCrossRefsLoading(false) }
  }

  function handleExport(org: string, repoName: string) {
    window.open(`/api/sbom/download?${new URLSearchParams({ org, repo: repoName })}`, "_blank")
  }

  function resetFilters() {
    setSearch(""); setDebouncedSearch("")
    setEcosystems([]); setSource(""); setRepos([])
    setVersionOp(""); setVersionValue(""); setVersionValueEnd("")
    setFilterLogic("and"); setPage(1)
    searchInputRef.current?.focus()
  }

  const parsedPackages = parseManifestInput(bulkInput)

  async function runBulkLookup() {
    if (!parsedPackages.length) return
    setBulkLoading(true)
    setBulkError(null)
    try {
      const result = await gqlQuery<{ sbomBulkLookup: BulkMatch[] }>(SBOM_BULK_LOOKUP_QUERY, { queries: parsedPackages })
      setBulkResults(result.sbomBulkLookup)
    } catch (e: any) {
      setBulkError(e.message || "Bulk lookup failed")
    } finally {
      setBulkLoading(false)
    }
  }

  const hasActiveFilters = debouncedSearch || ecosystems.length || source || repos.length || versionOp
  const activeGroupCount = (ecosystems.length ? 1 : 0) + (source ? 1 : 0) + (repos.length ? 1 : 0)
  const total = data?.total ?? 0
  const totalPages = data?.totalPages ?? 0

  return (
    <div className="space-y-4">
      {/* Top bar: mode toggle + export */}
      <div className="flex items-center justify-between">
        <SegmentedControl
          ariaLabel="SBOM view mode"
          value={viewMode}
          onChange={setViewMode}
          options={[
            { id: "search", label: "Search" },
            { id: "bulk",   label: "Bulk Lookup" },
          ]}
        />

        {isEnterprise ? (
          <Button
            variant="secondary"
            size="sm"
            disabled={!repos.length}
            onClick={() => { if (repos[0] && data?.items[0]) handleExport(data.items[0].org, repos[0]) }}
            title={repos.length ? `Export CycloneDX SBOM for ${repos[0]}` : "Select a repository to export"}
            leadingIcon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3" />
              </svg>
            }
          >
            Export SBOM
          </Button>
        ) : (
          <a href="/settings/license" className="flex items-center gap-1.5 rounded-lg border border-[var(--color-argus-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-argus)] transition-colors hover:bg-[var(--color-argus-subtle)] focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none">
            <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
              <path d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
            </svg>
            Export SBOM
            <span className="rounded-full bg-[var(--color-argus-subtle)] px-1.5 py-px text-2xs font-semibold">Enterprise</span>
          </a>
        )}
      </div>

      {viewMode === "bulk" ? (
        <BulkLookupPanel
          input={bulkInput}
          onInputChange={setBulkInput}
          parsedCount={parsedPackages.length}
          results={bulkResults}
          loading={bulkLoading}
          error={bulkError}
          onRun={runBulkLookup}
        />
      ) : (
        <>
          {/* Search and filters */}
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4 space-y-3">
            {/* Row 1: search + multi-selects */}
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
              <div className="flex-1">
                <Input
                  ref={searchInputRef}
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search packages by name, version, or PURL..."
                  leadingIcon={(
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
                      <path d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
                    </svg>
                  )}
                />
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                <MultiSelect label="Ecosystems" options={filters?.ecosystems ?? []} selected={ecosystems} onChange={(v) => { setEcosystems(v); setPage(1) }} />

                <Select
                  value={source}
                  onChange={(e) => { setSource(e.target.value); setPage(1) }}
                  className="w-auto"
                >
                  <option value="">All sources</option>
                  <option value="dependencies">Dependencies</option>
                  <option value="containers">Containers</option>
                </Select>

                <MultiSelect label="Repositories" options={filters?.repositories ?? []} selected={repos} onChange={(v) => { setRepos(v); setPage(1) }} />
              </div>
            </div>

            {/* Row 2: version filter */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-medium text-[var(--color-text-secondary)]">Version</span>
              <Select
                size="sm"
                value={versionOp}
                onChange={(e) => { setVersionOp(e.target.value as VersionOp); setPage(1) }}
                className="w-auto"
              >
                <option value="">Any</option>
                <option value="eq">Exact (=)</option>
                <option value="gte">At least (≥)</option>
                <option value="lte">At most (≤)</option>
                <option value="range">Range</option>
              </Select>
              {versionOp && (
                <Input
                  size="sm"
                  type="text"
                  value={versionValue}
                  onChange={(e) => { setVersionValue(e.target.value); setPage(1) }}
                  placeholder={versionOp === "range" ? "From (e.g. 1.0.0)" : "e.g. 4.17.21"}
                  className="w-36 font-mono"
                />
              )}
              {versionOp === "range" && (
                <>
                  <span className="text-xs text-[var(--color-text-tertiary)]">to</span>
                  <Input
                    size="sm"
                    type="text"
                    value={versionValueEnd}
                    onChange={(e) => { setVersionValueEnd(e.target.value); setPage(1) }}
                    placeholder="To (e.g. 2.0.0)"
                    className="w-36 font-mono"
                  />
                </>
              )}

              <div className="ml-auto flex items-center gap-2">
                {hasActiveFilters && (
                  <Button variant="secondary" size="sm" onClick={resetFilters}>
                    Clear
                  </Button>
                )}
                <SegmentedControl
                  ariaLabel="Filter logic"
                  value={filterLogic}
                  onChange={(next) => { setFilterLogic(next); setPage(1) }}
                  options={[
                    { id: "and", label: "AND" },
                    { id: "or",  label: "OR" },
                  ]}
                />
              </div>
            </div>

            {/* Result count */}
            <p className="text-xs text-[var(--color-text-secondary)] tabular-nums">
              {loading ? <span className="motion-safe:animate-pulse">Searching...</span> : <>{total.toLocaleString()} component{total !== 1 ? "s" : ""} found</>}
            </p>
          </div>

          {/* Error */}
          {error && (
            <div className="rounded-xl border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3">
              <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>
              <button type="button" onClick={fetchData} className="mt-1 text-xs font-medium text-[var(--color-severity-critical)] underline underline-offset-2 hover:no-underline focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none">Retry</button>
            </div>
          )}

          {/* Results table */}
          {!error && (
            <div className="overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)]">
              <div className="overflow-x-auto">
                <Table>
                  <Thead>
                    <Tr>
                      <Th>Package</Th>
                      <Th>Version</Th>
                      <Th>Ecosystem</Th>
                      <Th>Source</Th>
                      <Th>Repository</Th>
                      <Th>Scanned</Th>
                      <Th className="text-right">Actions</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {loading && !data ? (
                      Array.from({ length: 8 }).map((_, i) => (
                        <Tr key={i}>
                          {Array.from({ length: 7 }).map((_, j) => (
                            <Td key={j}><div className="h-4 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" style={{ width: `${45 + ((i * 7 + j) * 13 % 35)}%` }} /></Td>
                          ))}
                        </Tr>
                      ))
                    ) : data?.items.length === 0 ? (
                      <Tr>
                        <Td colSpan={7} className="px-4 py-12 text-center">
                          <p className="text-sm text-[var(--color-text-secondary)]">
                            {hasActiveFilters ? "No components match your filters." : "No SBOM data available. Run a scan to generate SBOMs."}
                          </p>
                          {hasActiveFilters && (
                            <button type="button" onClick={resetFilters} className="mt-2 text-xs font-medium text-[var(--color-accent)] hover:underline focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none">Clear filters</button>
                          )}
                        </Td>
                      </Tr>
                    ) : (
                      data?.items.map((item) => (
                        <ComponentRow
                          key={`${item.org}:${item.repo}:${item.purl}`}
                          item={item}
                          isExpanded={expandedPurl === item.purl}
                          onToggle={() => toggleCrossRef(item.purl)}
                          crossRefs={expandedPurl === item.purl ? crossRefs : []}
                          crossRefsLoading={expandedPurl === item.purl && crossRefsLoading}
                          isEnterprise={isEnterprise}
                          onExport={handleExport}
                        />
                      ))
                    )}
                  </Tbody>
                </Table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between border-t border-[var(--color-border)] px-4 py-3">
                  <p className="text-xs text-[var(--color-text-secondary)] tabular-nums">Page {page} of {totalPages}</p>
                  <div className="flex gap-1">
                    <Button variant="secondary" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                      Previous
                    </Button>
                    <Button variant="secondary" size="sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                      Next
                    </Button>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Bulk Lookup Panel
// ---------------------------------------------------------------------------

function BulkLookupPanel({
  input, onInputChange, parsedCount, results, loading, error, onRun,
}: {
  input: string; onInputChange: (v: string) => void; parsedCount: number
  results: BulkMatch[] | null; loading: boolean; error: string | null
  onRun: () => void
}) {
  const found = results?.filter((r) => r.found).length ?? 0
  const notFound = results?.filter((r) => !r.found).length ?? 0

  return (
    <div className="space-y-4">
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4 space-y-3">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
            Bulk exposure check
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            Paste package names, PURLs, or a manifest file. Supports package.json, requirements.txt, go.mod, Gemfile, and Cargo.toml.
          </p>
        </div>
        <Textarea
          value={input}
          onChange={(e) => onInputChange(e.target.value)}
          rows={8}
          placeholder={"lodash\nlog4j-core\npkg:npm/express@4.18.2\nrequests\nflask"}
          className="font-mono text-xs"
        />
        <div className="flex items-center justify-between">
          <p className="text-xs text-[var(--color-text-secondary)] tabular-nums">
            {parsedCount} package{parsedCount !== 1 ? "s" : ""} detected
          </p>
          <button
            type="button"
            disabled={!parsedCount || loading}
            onClick={onRun}
            className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-xs font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] disabled:opacity-40 disabled:cursor-not-allowed focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:outline-none"
          >
            {loading ? "Checking..." : "Check Exposure"}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3">
          <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>
        </div>
      )}

      {results && (
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden">
          {/* Summary bar */}
          <div className="flex items-center gap-4 border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
            <p className="text-xs font-medium text-[var(--color-text-primary)]">
              {results.length} checked
            </p>
            <span className="flex items-center gap-1.5 text-xs">
              <span className="h-2 w-2 rounded-full bg-[var(--color-severity-critical)]" />
              <span className="font-semibold tabular-nums text-[var(--color-severity-critical)]">{found}</span>
              <span className="text-[var(--color-text-secondary)]">found in estate</span>
            </span>
            <span className="flex items-center gap-1.5 text-xs">
              <span className="h-2 w-2 rounded-full bg-[var(--color-status-ok)]" />
              <span className="font-semibold tabular-nums text-[var(--color-state-fixed)]">{notFound}</span>
              <span className="text-[var(--color-text-secondary)]">not found</span>
            </span>
          </div>

          {/* Results list */}
          <div className="divide-y divide-[var(--color-border)]">
            {results.map((r, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-2.5 text-xs">
                {r.found ? (
                  <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[var(--color-severity-critical-subtle)]" title="Found in estate">
                    <svg className="h-3 w-3 text-[var(--color-severity-critical)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
                      <path d="M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 3.75h.008v.008H12v-.008Z" />
                    </svg>
                  </span>
                ) : (
                  <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[var(--color-state-fixed-subtle)]" title="Not found">
                    <svg className="h-3 w-3 text-[var(--color-state-fixed)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
                      <path d="M5 13l4 4L19 7" />
                    </svg>
                  </span>
                )}
                <code className="font-mono font-medium text-[var(--color-text-primary)]">{r.query}</code>
                {r.found && (
                  <>
                    <EcosystemBadge ecosystem={r.ecosystem} />
                    <code className="font-mono text-[var(--color-text-tertiary)]">{r.version}</code>
                    <span className="text-[var(--color-text-secondary)]">
                      in {r.repos.length} repo{r.repos.length !== 1 ? "s" : ""}
                    </span>
                    <span className="ml-auto text-[var(--color-text-tertiary)] max-w-[300px] truncate" title={r.repos.join(", ")}>
                      {r.repos.join(", ")}
                    </span>
                  </>
                )}
                {!r.found && (
                  <span className="text-[var(--color-text-tertiary)]">Not in any repository</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Component Row
// ---------------------------------------------------------------------------

function ComponentRow({
  item, isExpanded, onToggle, crossRefs, crossRefsLoading, isEnterprise, onExport,
}: {
  item: SbomComponent; isExpanded: boolean; onToggle: () => void
  crossRefs: CrossRef[]; crossRefsLoading: boolean
  isEnterprise: boolean; onExport: (org: string, repo: string) => void
}) {
  return (
    <>
      <Tr interactive>
        <Td>
          <button type="button" onClick={onToggle} className="group flex items-center gap-2 text-left focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none focus-visible:rounded">
            <svg className={`h-3.5 w-3.5 shrink-0 text-[var(--color-text-tertiary)] transition-transform ${isExpanded ? "rotate-90" : ""}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <path d="m9 18 6-6-6-6" />
            </svg>
            <span className="font-medium text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)]">{item.name}</span>
          </button>
        </Td>
        <Td><code className="font-mono text-xs text-[var(--color-text-secondary)]">{item.version}</code></Td>
        <Td><EcosystemBadge ecosystem={item.ecosystem} /></Td>
        <Td><SourceBadge sourceTool={item.sourceTool} /></Td>
        <Td><span className="text-xs text-[var(--color-text-secondary)]">{item.repo}</span></Td>
        <Td><span className="text-xs text-[var(--color-text-tertiary)]" title={item.scannedAt}>{timeAgo(item.scannedAt)}</span></Td>
        <Td className="text-right">
          {isEnterprise ? (
            <Button variant="secondary" size="xs" onClick={() => onExport(item.org, item.repo)} title="Download CycloneDX SBOM">Export</Button>
          ) : (
            <span className="rounded-full bg-[var(--color-argus-subtle)] px-2 py-0.5 text-2xs font-semibold text-[var(--color-argus)]" title="SBOM export requires an Enterprise license">Enterprise</span>
          )}
        </Td>
      </Tr>

      {isExpanded && (
        <Tr>
          <Td colSpan={7} className="bg-[var(--color-bg)] px-4 py-0">
            <div className="py-3 pl-8">
              <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
                Found in {crossRefsLoading ? "..." : `${crossRefs.length} repositor${crossRefs.length !== 1 ? "ies" : "y"}`}
              </p>
              {crossRefsLoading ? (
                <div className="space-y-2">
                  {[1, 2].map((i) => <div key={i} className="h-4 w-64 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />)}
                </div>
              ) : crossRefs.length === 0 ? (
                <p className="text-xs text-[var(--color-text-secondary)]">No cross-references found.</p>
              ) : (
                <div className="space-y-1">
                  {crossRefs.map((r) => (
                    <div key={`${r.org}:${r.repo}`} className="flex items-center gap-3 rounded-lg px-3 py-1.5 text-xs transition-colors hover:bg-[var(--color-surface-raised)]">
                      <span className="font-medium text-[var(--color-text-primary)]">{r.repo}</span>
                      <code className="font-mono text-[var(--color-text-tertiary)]">{r.version}</code>
                      <SourceBadge sourceTool={r.sourceTool} />
                      <span className="ml-auto text-[var(--color-text-tertiary)]">{timeAgo(r.scannedAt)}</span>
                      {isEnterprise && (
                        <Button variant="secondary" size="xs" onClick={() => window.open(`/api/sbom/download?${new URLSearchParams({ org: r.org, repo: r.repo })}`, "_blank")}>Export</Button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Td>
        </Tr>
      )}
    </>
  )
}
