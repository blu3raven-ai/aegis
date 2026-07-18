"use client"

import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { gqlQuery, isQuerySyntaxError } from "@/lib/client/graphql-client"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { Skeleton } from "@/components/ui/Skeleton"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import { Textarea } from "@/components/ui/Textarea"
import { CommandBar, type AttributeDef } from "@/components/shared/command-bar"
import { ComponentVulnBadge } from "@/components/shared/sbom/ComponentVulnBadge"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"
import { ComponentLicenseBadge } from "@/components/shared/sbom/ComponentLicenseBadge"
import { DependencyOriginBadge } from "@/components/shared/sbom/DependencyOriginBadge"
import type { ComponentVulns, DependencyOrigin } from "@/lib/client/sbom-api"
import { CATEGORY_META, type LicenseCategory } from "@/lib/sbom/license-category"
import { bucketBulkMatches, type BulkExposure, type BulkOccurrence } from "@/lib/sbom/bulk-exposure"

function originFromIsDirect(d: boolean | null): DependencyOrigin {
  return d === true ? "direct" : d === false ? "transitive" : "unknown"
}

// ---------------------------------------------------------------------------
// GraphQL queries
// ---------------------------------------------------------------------------

const SBOM_SEARCH_QUERY = `
  query SbomSearch(
    $search: String, $ecosystems: [String!], $source: String,
    $repos: [String!], $versionOp: String, $versionValue: String,
    $versionValueEnd: String, $filterLogic: String, $vulnerableOnly: Boolean,
    $licenseCategories: [String!], $dependency: String, $page: Int, $perPage: Int
  ) {
    sbom {
      search(
        search: $search, ecosystems: $ecosystems, source: $source,
        repos: $repos, versionOp: $versionOp, versionValue: $versionValue,
        versionValueEnd: $versionValueEnd, filterLogic: $filterLogic,
        vulnerableOnly: $vulnerableOnly, licenseCategories: $licenseCategories,
        dependency: $dependency, page: $page, perPage: $perPage
      ) {
        items {
          name version ecosystem purl repo org isContainer scannedAt
          license licenseCategory isDirect
          vulns { critical high medium low total }
        }
        total page perPage totalPages truncated
      }
    }
  }
`

const SBOM_FILTER_OPTIONS_QUERY = `
  query SbomFilterOptions {
    sbom {
      filterOptions { ecosystems repositories sources licenseCategories dependencyScopes }
    }
  }
`

const SBOM_BULK_LOOKUP_QUERY = `
  query SbomBulkLookup($queries: [String!]!) {
    sbom {
      bulkLookup(queries: $queries) {
        matches {
          query found name ecosystem purl queriedVersion exposure
          occurrences { repo version flagged latent }
          occurrenceTotal occurrencesTruncated
          license licenseCategory
        }
        truncated inputTruncated acceptedCount
      }
    }
  }
`

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SbomComponent {
  name: string; version: string; ecosystem: string; purl: string
  repo: string; org: string; isContainer: boolean; scannedAt: string
  license: string | null; licenseCategory: LicenseCategory | null
  isDirect: boolean | null
  vulns: ComponentVulns
}

interface SbomSearchResult {
  sbom: {
    search: {
      items: SbomComponent[]; total: number; page: number
      perPage: number; totalPages: number; truncated: boolean
    }
  }
}

interface SbomFilterResult {
  sbom: {
    filterOptions: {
      ecosystems: string[]; repositories: string[]; sources: string[]
      licenseCategories: string[]; dependencyScopes: string[]
    }
  }
}

interface BulkMatch {
  query: string; found: boolean; name: string
  ecosystem: string; purl: string
  queriedVersion: string | null; exposure: BulkExposure
  occurrences: BulkOccurrence[]
  occurrenceTotal: number; occurrencesTruncated: boolean
  license: string | null; licenseCategory: LicenseCategory | null
  // Index signature so the match satisfies bucketBulkMatches' constraint.
  [key: string]: unknown
}

interface BulkResult {
  matches: BulkMatch[]; truncated: boolean
  inputTruncated: boolean; acceptedCount: number
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

    // PURL: pkg:ecosystem/name@version — keep the version; the lookup flags it.
    if (line.startsWith("pkg:")) { parsed.push(line); continue }

    // Plain package name (alphanumeric, dots, hyphens, underscores, slashes)
    const plainMatch = line.match(/^([a-zA-Z0-9@_./-]+)/)
    if (plainMatch) { parsed.push(plainMatch[1]); continue }
  }

  return [...new Set(parsed)]
}

type VersionOp = "" | "eq" | "gt" | "gte" | "lt" | "lte" | "range"
type ViewMode = "search" | "bulk"

/** Parse a free-text version constraint (e.g. "≥4.17.21", ">2.0", "<2.0",
 * "1.0..2.0") into the operator + value(s) the search API expects. Bare text
 * means "=". `>=`/`<=` must precede the bare `>`/`<` in the alternation. */
function parseVersion(text: string): { op: VersionOp; val: string; end: string } {
  const t = text.trim()
  if (!t) return { op: "", val: "", end: "" }
  if (t.includes("..")) {
    const [a, b] = t.split("..")
    return { op: "range", val: a.trim(), end: (b ?? "").trim() }
  }
  const m = t.match(/^\s*(>=|≥|<=|≤|>|<|=)?\s*(.*)$/)
  const sym = m?.[1] ?? ""
  const val = (m?.[2] ?? t).trim()
  const op: VersionOp =
    sym === ">=" || sym === "≥" ? "gte"
      : sym === "<=" || sym === "≤" ? "lte"
        : sym === ">" ? "gt"
          : sym === "<" ? "lt"
            : "eq"
  return { op, val, end: "" }
}

/** Render the active version constraint back into a compact chip label. */
function formatVersion(op: VersionOp, val: string, end: string): string {
  if (op === "range") return `${val}..${end}`
  const sym =
    op === "gte" ? "≥" : op === "gt" ? ">" : op === "lte" ? "≤" : op === "lt" ? "<" : "="
  return `${sym} ${val}`.trim()
}

// ---------------------------------------------------------------------------
// Small components
// ---------------------------------------------------------------------------

function EcosystemBadge({ ecosystem }: { ecosystem: string }) {
  // Neutral semantic tint for every ecosystem — the text label already
  // identifies it, so a per-ecosystem colour adds noise without information.
  return (
    <span className="inline-flex rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5 text-2xs font-semibold text-[var(--color-text-primary)]">
      {ecosystem}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function SbomExplorer() {
  const [viewMode, setViewMode] = useState<ViewMode>("search")

  // Search filters
  const [search, setSearch] = useState("")
  const [debouncedSearch, setDebouncedSearch] = useState("")
  const [ecosystems, setEcosystems] = useState<string[]>([])
  const [source, setSource] = useState("")
  const [repos, setRepos] = useState<string[]>([])
  const [licenseCategories, setLicenseCategories] = useState<string[]>([])
  const [dependency, setDependency] = useState("")
  const [versionOp, setVersionOp] = useState<VersionOp>("")
  const [versionValue, setVersionValue] = useState("")
  const [versionValueEnd, setVersionValueEnd] = useState("")
  const [vulnerableOnly, setVulnerableOnly] = useState(false)
  const [page, setPage] = useState(1)
  const perPage = 50

  const [data, setData] = useState<SbomSearchResult["sbom"]["search"] | null>(null)
  const [filters, setFilters] = useState<SbomFilterResult["sbom"]["filterOptions"] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // Distinct from `error` (the red banner): a user-correctable query-syntax
  // problem, surfaced as a non-alarming inline hint under the search bar.
  const [searchSyntaxError, setSearchSyntaxError] = useState<string | null>(null)
  const [showSearchHelp, setShowSearchHelp] = useState(false)

  // Bulk lookup
  const [bulkInput, setBulkInput] = useState("")
  const [bulkResults, setBulkResults] = useState<BulkResult | null>(null)
  const [bulkLoading, setBulkLoading] = useState(false)
  const [bulkError, setBulkError] = useState<string | null>(null)

  // Debounce search
  useEffect(() => {
    const t = setTimeout(() => { setDebouncedSearch(search); setPage(1) }, 300)
    return () => clearTimeout(t)
  }, [search])

  // Load filter options
  useEffect(() => {
    gqlQuery<SbomFilterResult>(SBOM_FILTER_OPTIONS_QUERY)
      .then((r) => setFilters(r.sbom.filterOptions))
      .catch(() => {})
  }, [])

  // Main search. A monotonic sequence guards against out-of-order responses:
  // a slow earlier fetch (e.g. from a rapid facet change) can't overwrite the
  // result of a newer one. Mirrors RiskyComponentsView.
  const fetchSeqRef = useRef(0)
  const fetchData = useCallback(async () => {
    const seq = ++fetchSeqRef.current
    setLoading(true)
    setError(null)
    setSearchSyntaxError(null)
    try {
      const result = await gqlQuery<SbomSearchResult>(SBOM_SEARCH_QUERY, {
        search: debouncedSearch || null,
        ecosystems: ecosystems.length ? ecosystems : null,
        source: source || null,
        repos: repos.length ? repos : null,
        versionOp: versionOp || null,
        versionValue: versionValue || null,
        versionValueEnd: versionValueEnd || null,
        filterLogic: "and",
        vulnerableOnly,
        licenseCategories: licenseCategories.length ? licenseCategories : null,
        dependency: dependency || null,
        page,
        perPage,
      })
      if (fetchSeqRef.current !== seq) return // superseded by a newer fetch
      setData(result.sbom.search)
    } catch (e: any) {
      if (fetchSeqRef.current !== seq) return
      // A malformed search query is user-correctable: show an inline hint, not
      // the red "failed to load" banner that implies a backend outage.
      if (isQuerySyntaxError(e)) {
        setSearchSyntaxError(e.message || "Invalid search query.")
      } else {
        setError(e.message || "Failed to load SBOM data")
      }
    } finally {
      if (fetchSeqRef.current === seq) setLoading(false)
    }
  }, [debouncedSearch, ecosystems, source, repos, licenseCategories, dependency, versionOp, versionValue, versionValueEnd, vulnerableOnly, page, perPage])

  useEffect(() => { fetchData() }, [fetchData])

  function handleExport(repoName: string) {
    // repoName is the "owner/name" display_name; the /repo path alias resolves
    // it to the caller-scoped latest SBOM (the same endpoint the repo-detail
    // page uses). Gated only on view access — available to every tier.
    window.open(`/api/v1/sboms/repo/${encodeURIComponent(repoName)}?format=cyclonedx-json`, "_blank")
  }

  function resetFilters() {
    setSearch(""); setDebouncedSearch("")
    setEcosystems([]); setSource(""); setRepos([]); setLicenseCategories([]); setDependency("")
    setVersionOp(""); setVersionValue(""); setVersionValueEnd("")
    setVulnerableOnly(false); setPage(1)
  }

  // Faceted command-bar filter catalog (matches the Findings search pattern).
  const filterAttributes = useMemo<AttributeDef[]>(
    () => [
      {
        key: "ecosystem", label: "ecosystem", group: "Package", description: "Package ecosystem",
        type: "enum", options: (filters?.ecosystems ?? []).map((e) => ({ value: e, label: e })),
      },
      {
        key: "source", label: "source", group: "Package", description: "Dependency or container",
        type: "enum",
        options: [
          { value: "dependencies", label: "Dependencies" },
          { value: "containers", label: "Containers" },
        ],
      },
      {
        key: "repo", label: "repo", group: "Package", description: "Repository",
        type: "enum", options: (filters?.repositories ?? []).map((r) => ({ value: r, label: r })),
      },
      {
        key: "version", label: "version", group: "Package",
        description: "e.g. ≥4.17.21 or 1.0..2.0", type: "text", placeholder: "≥4.17.21",
      },
      {
        key: "vulnerable", label: "vulnerable", group: "Risk",
        description: "Has open vulnerabilities", type: "boolean", variant: "danger",
        options: [{ value: "true", label: "Yes" }, { value: "false", label: "No" }],
      },
      {
        key: "license", label: "license", group: "Risk", description: "License risk category",
        type: "enum",
        options: (filters?.licenseCategories ?? []).map((c) => ({
          value: c, label: CATEGORY_META[c as LicenseCategory]?.label ?? c,
        })),
      },
      {
        key: "origin", label: "origin", group: "Package", description: "Direct, transitive, or unknown",
        type: "enum",
        options: (filters?.dependencyScopes ?? []).map((s) => ({
          value: s, label: s.charAt(0).toUpperCase() + s.slice(1),
        })),
      },
    ],
    [filters],
  )

  const filterValues: Record<string, string | null> = {
    ecosystem: ecosystems[0] ?? null,
    source: source || null,
    repo: repos[0] ?? null,
    version: versionOp ? formatVersion(versionOp, versionValue, versionValueEnd) : null,
    vulnerable: vulnerableOnly ? "true" : null,
    license: licenseCategories[0] ?? null,
    origin: dependency || null,
  }

  function handleFilterChange(key: string, value: string | null) {
    setPage(1)
    switch (key) {
      case "ecosystem": setEcosystems(value ? [value] : []); break
      case "source": setSource(value ?? ""); break
      case "repo": setRepos(value ? [value] : []); break
      case "vulnerable": setVulnerableOnly(value === "true"); break
      case "license": setLicenseCategories(value ? [value] : []); break
      case "origin": setDependency(value ?? ""); break
      case "version": {
        const { op, val, end } = parseVersion(value ?? "")
        setVersionOp(op); setVersionValue(val); setVersionValueEnd(end)
        break
      }
    }
  }

  const parsedPackages = parseManifestInput(bulkInput)

  async function runBulkLookup() {
    if (!parsedPackages.length) return
    setBulkLoading(true)
    setBulkError(null)
    try {
      const result = await gqlQuery<{ sbom: { bulkLookup: BulkResult } }>(SBOM_BULK_LOOKUP_QUERY, { queries: parsedPackages })
      setBulkResults(result.sbom.bulkLookup)
    } catch (e: any) {
      setBulkError(e.message || "Bulk lookup failed")
    } finally {
      setBulkLoading(false)
    }
  }

  const hasActiveFilters = debouncedSearch || ecosystems.length || source || repos.length || licenseCategories.length || dependency || versionOp || vulnerableOnly
  const total = data?.total ?? 0
  const totalPages = data?.totalPages ?? 0
  // Version filters scan a bounded candidate set; when capped the count/pages
  // reflect only that prefix, so the count is shown as "N+" with a note.
  const truncated = data?.truncated ?? false

  return (
    <div className="space-y-4">
      {/* Top bar: mode toggle */}
      <div className="flex items-center justify-between">
        <SegmentedControl
          ariaLabel="SBOM view mode"
          value={viewMode}
          onChange={setViewMode}
          options={[
            { id: "search", label: "Search" },
            { id: "bulk",   label: "Bulk Exposure" },
          ]}
        />
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
          {/* Faceted command bar — same search pattern as the Findings tab */}
          <CommandBar
            attributes={filterAttributes}
            values={filterValues}
            onChange={handleFilterChange}
            searchInput={search}
            onSearchInputChange={setSearch}
            searchPlaceholder="Search: lodash OR axios · ecosystem:npm · name:log4j*"
          />

          {/* Syntax-error hint (amber, non-alarming) — distinct from the red error banner */}
          {searchSyntaxError && (
            <div
              role="status"
              aria-live="polite"
              className="flex items-start gap-2 rounded-md border border-[var(--color-severity-medium-border)] bg-[var(--color-severity-medium-subtle)] px-3 py-2"
            >
              <svg className="mt-px h-3.5 w-3.5 shrink-0 text-[var(--color-severity-medium-text)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
              </svg>
              <p className="text-xs text-[var(--color-text-secondary)]">{searchSyntaxError}</p>
            </div>
          )}

          <div className="flex items-center justify-between">
            <span className="text-xs text-[var(--color-text-secondary)] tabular-nums">
              {loading
                ? "Searching…"
                : `${total.toLocaleString()}${truncated ? "+" : ""} component${total !== 1 ? "s" : ""}`}
            </span>
            <div className="flex items-center gap-2">
              <SearchSyntaxTrigger open={showSearchHelp} onToggle={() => setShowSearchHelp((v) => !v)} />
              {hasActiveFilters && (
                <Button variant="ghost" size="xs" onClick={resetFilters}>
                  Clear all
                </Button>
              )}
              <Button
                variant="secondary"
                size="sm"
                disabled={!repos.length}
                onClick={() => { if (repos[0]) handleExport(repos[0]) }}
                title={repos.length ? `Export CycloneDX SBOM for ${repos[0]}` : "Select a repository to export"}
                leadingIcon={
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3" />
                  </svg>
                }
              >
                Export SBOM
              </Button>
            </div>
          </div>

          {/* Expandable search-syntax reference, full-width beneath the count row */}
          {showSearchHelp && <SearchSyntaxPanel />}

          {truncated && !loading && (
            <p className="text-2xs text-[var(--color-text-secondary)]">
              Showing the first {total.toLocaleString()} matches. This version filter scanned too many
              components to be exhaustive. Add an ecosystem or repository filter for complete results.
            </p>
          )}

          {/* Error */}
          {error && (
            <div className="rounded-md border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3">
              <p className="text-sm text-[var(--color-severity-critical-text)]">{error}</p>
              <Button variant="link" size="sm" onClick={fetchData} className="mt-1 underline underline-offset-2 hover:no-underline">Retry</Button>
            </div>
          )}

          {/* Results table */}
          {!error && (
            <Card padding="none" className="overflow-hidden rounded-md">
              <div className="overflow-x-auto">
                <Table>
                  <Thead>
                    <Tr>
                      <Th>Package</Th>
                      <Th>Version</Th>
                      <Th>Vulnerabilities</Th>
                      <Th>License</Th>
                      <Th>Repository</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {loading && !data ? (
                      Array.from({ length: 8 }).map((_, i) => (
                        <Tr key={i}>
                          {Array.from({ length: 5 }).map((_, j) => (
                            <Td key={j}><Skeleton className="h-4" style={{ width: `${45 + ((i * 7 + j) * 13 % 35)}%` }} /></Td>
                          ))}
                        </Tr>
                      ))
                    ) : data?.items.length === 0 ? (
                      <Tr>
                        <Td colSpan={5} className="px-4 py-12 text-center">
                          <p className="text-sm text-[var(--color-text-secondary)]">
                            {hasActiveFilters ? "No components match your filters." : "No SBOM data available. Run a scan to generate SBOMs."}
                          </p>
                          {hasActiveFilters && (
                            <Button variant="link" size="sm" onClick={resetFilters} className="mt-2 hover:underline">Clear filters</Button>
                          )}
                        </Td>
                      </Tr>
                    ) : (
                      data?.items.map((item) => (
                        <ComponentRow
                          key={`${item.org}:${item.repo}:${item.purl}`}
                          item={item}
                          onExport={handleExport}
                        />
                      ))
                    )}
                  </Tbody>
                </Table>
              </div>

              {totalPages > 1 && (
                <PaginatedTableFooter
                  totalCount={total}
                  page={page}
                  perPage={perPage}
                  totalPages={totalPages}
                  onPageChange={setPage}
                  onPerPageChange={() => {}}
                  label="components"
                />
              )}
            </Card>
          )}
        </>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Search syntax help
// ---------------------------------------------------------------------------

/** Toggle that lives in the count/action row to keep the chrome compact. The
 * expandable panel renders separately, full-width, so it isn't cramped by the
 * right-aligned cluster. */
function SearchSyntaxTrigger({ open, onToggle }: { open: boolean; onToggle: () => void }) {
  return (
    <Button
      variant="ghost"
      size="xs"
      onClick={onToggle}
      aria-expanded={open}
      leadingIcon={
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm-1.2-6.75a1.2 1.2 0 0 1 .68-1.08c.74-.37 1.27-1 1.27-1.8a1.5 1.5 0 0 0-1.5-1.5c-.7 0-1.3.43-1.5 1.05M12 16.5h.008v.008H12V16.5Z" />
        </svg>
      }
    >
      Search syntax
    </Button>
  )
}

/** Full-width reference for the boolean search grammar. Rendered as a sibling
 * of the count row so its two-column panel gets the full content width. */
function SearchSyntaxPanel() {
  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
      <p className="text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
        Boolean search
      </p>
      <dl className="mt-2 grid gap-y-1.5 gap-x-4 sm:grid-cols-2">
        {[
          ["lodash OR axios", "either package"],
          ["name:log4j-core ecosystem:maven", "scoped to a field + ecosystem"],
          ["react -version:18.2.0", "exclude a version"],
          ['"react-dom" · name:lo* · repo:acme-org', "exact · wildcard · repo"],
        ].map(([code, desc]) => (
          <div key={code} className="flex flex-col gap-0.5">
            <code className="font-mono text-xs text-[var(--color-text-primary)]">{code}</code>
            <span className="text-2xs text-[var(--color-text-tertiary)]">{desc}</span>
          </div>
        ))}
      </dl>
      <p className="mt-3 text-2xs text-[var(--color-text-tertiary)]">
        Operators: <code className="font-mono text-[var(--color-text-secondary)]">AND OR NOT - ( )</code> ·
        Fields: <code className="font-mono text-[var(--color-text-secondary)]">name version ecosystem license repo source purl origin</code>
      </p>
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
  results: BulkResult | null; loading: boolean; error: string | null
  onRun: () => void
}) {
  const matches = results?.matches ?? []
  const { flaggedInUse, latent, present, otherVersions, notFound } = bucketBulkMatches(matches)
  const foundCount = flaggedInUse.length + latent.length + present.length + otherVersions.length

  return (
    <div className="space-y-4">
      <Card padding="none" className="rounded-md p-4 space-y-3">
        <div>
          <p className="text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
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
          <Button
            variant="primary"
            size="sm"
            disabled={!parsedCount}
            isLoading={loading}
            onClick={onRun}
          >
            Check Exposure
          </Button>
        </div>
      </Card>

      {error && (
        <div className="rounded-md border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3">
          <p className="text-sm text-[var(--color-severity-critical-text)]">{error}</p>
        </div>
      )}

      {loading && !results && (
        <div className="flex items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3" aria-live="polite">
          <span className="h-3.5 w-3.5 shrink-0 rounded-full border-2 border-[var(--color-accent)] border-t-transparent motion-safe:animate-spin" />
          <span className="text-sm text-[var(--color-text-tertiary)]">Checking exposure across your repositories…</span>
        </div>
      )}

      {results && (
        <Card padding="none" className="rounded-md overflow-hidden">
          {/* Summary bar */}
          <div className="flex items-center gap-4 border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-3">
            <p className="text-xs font-medium text-[var(--color-text-primary)]">
              {matches.length} checked
            </p>
            <span className="flex items-center gap-1.5 text-xs">
              <span className="h-2 w-2 rounded-full bg-[var(--color-text-primary)]" />
              <span className="font-semibold tabular-nums text-[var(--color-text-primary)]">{foundCount}</span>
              <span className="text-[var(--color-text-secondary)]">in estate</span>
            </span>
            <span className="flex items-center gap-1.5 text-xs">
              <span className="h-2 w-2 rounded-full bg-[var(--color-status-ok)]" />
              <span className="font-semibold tabular-nums text-[var(--color-status-ok-text)]">{notFound.length}</span>
              <span className="text-[var(--color-text-secondary)]">not found</span>
            </span>
          </div>

          {results.truncated && (
            <div className="flex items-start gap-2 border-b border-[var(--color-severity-medium-border)] bg-[var(--color-severity-medium-subtle)] px-4 py-2.5">
              <svg className="mt-px h-3.5 w-3.5 shrink-0 text-[var(--color-severity-medium-text)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
              </svg>
              <p className="text-xs text-[var(--color-text-secondary)]">
                Too many matches to scan exhaustively. Some packages may show fewer repositories than they actually appear in, or read as not found. Narrow the list to get complete results.
              </p>
            </div>
          )}

          {results.inputTruncated && (
            <div className="flex items-start gap-2 border-b border-[var(--color-severity-medium-border)] bg-[var(--color-severity-medium-subtle)] px-4 py-2.5">
              <svg className="mt-px h-3.5 w-3.5 shrink-0 text-[var(--color-severity-medium-text)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
              </svg>
              <p className="text-xs text-[var(--color-text-secondary)]">
                Only the first {results.acceptedCount.toLocaleString()} of {parsedCount.toLocaleString()} pasted packages were checked. The rest aren&apos;t in any bucket below. Split the list into smaller batches to check them all.
              </p>
            </div>
          )}

          {/* Exposure-bucketed sections, most-actionable first. */}
          <BulkExposureSection
            label="In use at flagged version"
            count={flaggedInUse.length}
            tone="danger"
            matches={flaggedInUse}
          />
          <BulkExposureSection
            label="Loose range: a clean reinstall could pull the flagged version"
            count={latent.length}
            tone="warning"
            matches={latent}
          />
          <BulkExposureSection
            label="Present"
            count={present.length}
            tone="neutral"
            matches={present}
          />
          <BulkExposureSection
            label="Present at other versions"
            count={otherVersions.length}
            tone="muted"
            matches={otherVersions}
          />
          {notFound.length > 0 && (
            <div>
              <BulkSectionHeader label="Not found in any repo" count={notFound.length} tone="muted" />
              <div className="flex flex-wrap items-center gap-1.5 px-4 py-3">
                {notFound.slice(0, MAX_OCCURRENCE_CHIPS).map((r, i) => (
                  <span key={i} className="inline-flex rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-2 py-0.5 font-mono text-2xs text-[var(--color-text-tertiary)]">
                    {r.query}
                  </span>
                ))}
                {notFound.length > MAX_OCCURRENCE_CHIPS && (
                  <span className="text-2xs tabular-nums text-[var(--color-text-tertiary)]">
                    +{notFound.length - MAX_OCCURRENCE_CHIPS} more
                  </span>
                )}
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  )
}

// Max occurrence chips rendered per package before collapsing to "+N more".
const MAX_OCCURRENCE_CHIPS = 8

type BulkSectionTone = "danger" | "neutral" | "warning" | "muted"

const SECTION_DOT: Record<BulkSectionTone, string> = {
  danger: "bg-[var(--color-severity-critical)]",
  warning: "bg-[var(--color-severity-medium)]",
  neutral: "bg-[var(--color-accent)]",
  muted: "bg-[var(--color-text-tertiary)]",
}

function BulkSectionHeader({ label, count, tone }: { label: string; count: number; tone: BulkSectionTone }) {
  return (
    <div className="flex items-center gap-2 border-y border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-2">
      <span className={`h-2 w-2 rounded-full ${SECTION_DOT[tone]}`} />
      <p className="text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        {label}
      </p>
      <span className="tabular-nums text-2xs text-[var(--color-text-tertiary)]">{count}</span>
    </div>
  )
}

function OccurrenceChip({ occ }: { occ: BulkOccurrence }) {
  let cls = "border-[var(--color-border)] bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
  if (occ.flagged) {
    cls = "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]"
  } else if (occ.latent) {
    cls = "border-[var(--color-severity-medium-border)] bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium-text)]"
  }
  // Full identity in a tooltip so a truncated repo name is still recoverable,
  // and the flagged/latent state is stated in words (not conveyed by colour alone).
  let title = `${occ.repo} @ ${occ.version || "—"}`
  if (occ.flagged) {
    title = `${occ.repo} @ ${occ.version || "—"}: installed version matches the flagged version`
  } else if (occ.latent) {
    title = `${occ.repo} @ ${occ.version || "—"}: declared range could resolve to the flagged version on a clean reinstall`
  }
  return (
    <span title={title} className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-2xs ${cls}`}>
      {occ.flagged ? (
        <>
          {/* Non-colour marker for the flagged version (color-not-only). */}
          <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="h-3 w-3 shrink-0">
            <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
          </svg>
          <span className="sr-only">Flagged version in use: </span>
        </>
      ) : occ.latent ? (
        <>
          {/* Distinct non-colour marker for the latent "loose range" state. */}
          <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" className="h-3 w-3 shrink-0">
            <path d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99" />
          </svg>
          <span className="sr-only">Declared range could pull the flagged version: </span>
        </>
      ) : null}
      <span className="max-w-[160px] truncate">{occ.repo}</span>
      <span className="opacity-50">@</span>
      <span>{occ.version || "—"}</span>
    </span>
  )
}

function BulkExposureSection({
  label, count, tone, matches,
}: {
  label: string; count: number; tone: BulkSectionTone; matches: BulkMatch[]
}) {
  if (!matches.length) return null
  return (
    <div>
      <BulkSectionHeader label={label} count={count} tone={tone} />
      <div className="divide-y divide-[var(--color-border)]">
        {matches.map((r, i) => {
          const chips = r.occurrences.slice(0, MAX_OCCURRENCE_CHIPS)
          // Count off the TRUE occurrence total, not the per-query-capped list,
          // so a package in 200 repos reads "+192 more", not a capped figure.
          const more = r.occurrenceTotal - chips.length
          return (
            <div key={i} className="flex flex-wrap items-center gap-x-2 gap-y-1.5 px-4 py-2.5">
              <code className="font-mono text-xs font-medium text-[var(--color-text-primary)]">
                {r.name || r.query}
              </code>
              <EcosystemBadge ecosystem={r.ecosystem} />
              {r.licenseCategory && (
                <ComponentLicenseBadge spdxId={r.license} category={r.licenseCategory} />
              )}
              <div className="flex flex-wrap items-center gap-1">
                {chips.map((o, j) => <OccurrenceChip key={j} occ={o} />)}
                {more > 0 && (
                  <span
                    title={r.occurrences.slice(MAX_OCCURRENCE_CHIPS).map((o) => `${o.repo}@${o.version || "—"}`).join(", ")}
                    className="text-2xs tabular-nums text-[var(--color-text-tertiary)]"
                  >
                    +{more} more
                  </span>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Component Row
// ---------------------------------------------------------------------------

function ComponentRow({ item, onExport }: {
  item: SbomComponent
  onExport: (repo: string) => void
}) {
  return (
    <Tr interactive>
      <Td>
        <span className="font-medium text-[var(--color-text-primary)]">{item.name}</span>
        {/* Ecosystem + direct/transitive folded into the anchor cell instead of
            spending two columns on low-cardinality metadata. */}
        <div className="mt-0.5 flex items-center gap-1.5">
          <EcosystemBadge ecosystem={item.ecosystem} />
          <DependencyOriginBadge origin={originFromIsDirect(item.isDirect)} />
        </div>
      </Td>
      <Td><code className="font-mono text-xs text-[var(--color-text-secondary)]">{item.version}</code></Td>
      <Td><ComponentVulnBadge vulns={item.vulns} packageName={item.name} /></Td>
      <Td>
        {item.license || item.licenseCategory ? (
          <ComponentLicenseBadge spdxId={item.license} category={item.licenseCategory} />
        ) : (
          <span className="text-2xs text-[var(--color-text-tertiary)]">—</span>
        )}
      </Td>
      {/* One row per repo occurrence already, so the repo lives inline — no
          cross-ref drill-down. Search (e.g. name:foo) groups across repos. */}
      <Td>
        <div className="flex items-center justify-between gap-3">
          <span className="text-xs text-[var(--color-text-secondary)]">{item.repo}</span>
          {!item.isContainer && (
            <Button variant="secondary" size="xs" onClick={() => onExport(item.repo)}>Export</Button>
          )}
        </div>
      </Td>
    </Tr>
  )
}
