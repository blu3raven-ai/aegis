"use client"

import Link from "next/link"
import { Fragment, useCallback, useEffect, useRef, useState } from "react"
import { gqlQuery } from "@/lib/client/graphql-client"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import { CommandBar, type AttributeDef } from "@/components/shared/command-bar"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"
import type { ComponentVulns } from "@/lib/client/sbom-api"
import { ComponentLicenseBadge } from "@/components/shared/sbom/ComponentLicenseBadge"
import type { LicenseCategory } from "@/lib/sbom/license-category"
import { SourceBadge } from "../components/SourceBadge"

const SEV_TIERS = [
  { key: "critical", abbr: "C" },
  { key: "high", abbr: "H" },
  { key: "medium", abbr: "M" },
  { key: "low", abbr: "L" },
] as const

// Use the -text severity tokens (WCAG-safe on the light surface); the bare fill
// tokens fail 4.5:1 as text on white.
const SEV_COLOR: Record<(typeof SEV_TIERS)[number]["key"], string> = {
  critical: "text-[var(--color-severity-critical-text)]",
  high: "text-[var(--color-severity-high-text)]",
  medium: "text-[var(--color-severity-medium-text)]",
  low: "text-[var(--color-severity-low-text)]",
}

// A package name can appear as multiple ecosystem rows, so identify a row by
// (name, ecosystem). NUL separator (written as an escape, never a raw byte)
// can't occur in either value, so the key is unambiguous.
function rowKey(c: { packageName: string; ecosystem: string }): string {
  return `${c.packageName}\u0000${c.ecosystem}`
}

/** Per-tier open-finding counts (C/H/M/L) that make the risk ranking legible,
 * linking to the package's findings. Falls back to a neutral total when the
 * only open findings are unbucketed (e.g. informational). */
function SeverityBreakdown({ vulns, packageName, repo, showTotal = false }: { vulns: ComponentVulns; packageName: string; repo?: string; showTotal?: boolean }) {
  const present = SEV_TIERS.filter((t) => vulns[t.key] > 0)
  const findingWord = `open finding${vulns.total !== 1 ? "s" : ""}`
  // Spell the severities out for screen readers; the visual content is only
  // "5 C 9 H …" which announces meaninglessly.
  const ariaLabel =
    present.length > 0
      ? `${present.map((t) => `${vulns[t.key]} ${t.key}`).join(", ")} ${findingWord}. View in Findings`
      : `${vulns.total.toLocaleString()} ${findingWord}. View in Findings`
  // When scoped to one repo (the per-repo drill-down), carry that repo into the
  // Findings filter so the destination list matches the per-repo count clicked.
  const href = `/findings?q=${encodeURIComponent(packageName)}${repo ? `&repo=${encodeURIComponent(repo)}` : ""}`
  return (
    <Link
      href={href}
      title={`${vulns.total.toLocaleString()} ${findingWord}. View in Findings`}
      aria-label={ariaLabel}
      className="inline-flex items-center gap-2 rounded hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
    >
      {present.length > 0 ? (
        <>
          {present.map((t) => (
            <span key={t.key} className={`inline-flex items-baseline gap-0.5 tabular-nums ${SEV_COLOR[t.key]}`}>
              <span className="text-sm font-semibold">{vulns[t.key]}</span>
              <span className="text-2xs font-semibold">{t.abbr}</span>
            </span>
          ))}
          {showTotal && (
            <span className="text-2xs tabular-nums text-[var(--color-text-secondary)]">· {vulns.total.toLocaleString()}</span>
          )}
        </>
      ) : (
        <span className="text-2xs text-[var(--color-text-secondary)]">{vulns.total} open</span>
      )}
    </Link>
  )
}

const RISKY_COMPONENTS_QUERY = `
  query RiskyComponents($search: String, $ecosystems: [String!], $page: Int, $perPage: Int) {
    sbom {
      riskyComponents(search: $search, ecosystems: $ecosystems, page: $page, perPage: $perPage) {
        items {
          packageName
          ecosystem
          repoCount
          vulns { critical high medium low total }
          license
          licenseCategory
        }
        total
        page
        perPage
        totalPages
      }
    }
  }
`

const FILTER_OPTIONS_QUERY = `
  query SbomFilterOptions {
    sbom { filterOptions { ecosystems } }
  }
`

const PACKAGE_REPOS_QUERY = `
  query SbomPackageRepos($packageName: String!, $ecosystem: String) {
    sbom {
      packageRepos(packageName: $packageName, ecosystem: $ecosystem) {
        repo
        org
        isContainer
        vulns { critical high medium low total }
      }
    }
  }
`

interface PackageRepo {
  repo: string
  org: string
  isContainer: boolean
  vulns: ComponentVulns
}

interface RiskyComponent {
  packageName: string
  ecosystem: string
  repoCount: number
  vulns: ComponentVulns
  license: string | null
  licenseCategory: LicenseCategory | null
}

interface RiskyResult {
  sbom: {
    riskyComponents: {
      items: RiskyComponent[]
      total: number
      page: number
      perPage: number
      totalPages: number
    }
  }
}

const PER_PAGE = 25

export function RiskyComponentsView() {
  const [search, setSearch] = useState("")
  const [debouncedSearch, setDebouncedSearch] = useState("")
  const [ecosystem, setEcosystem] = useState("")
  const [page, setPage] = useState(1)

  const [data, setData] = useState<RiskyResult["sbom"]["riskyComponents"] | null>(null)
  const [ecosystems, setEcosystems] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // Monotonic token so a slow earlier page/filter fetch can't overwrite a
  // faster later one (the table query is debounced + paged, so overlaps happen).
  const fetchSeqRef = useRef(0)

  // "Where used" drill-down — affected repos for the expanded package.
  const [expandedPkg, setExpandedPkg] = useState<string | null>(null)
  const [pkgRepos, setPkgRepos] = useState<PackageRepo[]>([])
  const [pkgReposLoading, setPkgReposLoading] = useState(false)
  // Guards against out-of-order responses when expanding rows quickly.
  const pkgReqRef = useRef<string | null>(null)

  useEffect(() => {
    const t = setTimeout(() => {
      setDebouncedSearch(search)
      setPage(1)
    }, 300)
    return () => clearTimeout(t)
  }, [search])

  useEffect(() => {
    gqlQuery<{ sbom: { filterOptions: { ecosystems: string[] } } }>(FILTER_OPTIONS_QUERY)
      .then((r) => setEcosystems(r.sbom.filterOptions.ecosystems))
      .catch(() => {})
  }, [])

  const fetchData = useCallback(async () => {
    const seq = ++fetchSeqRef.current
    setLoading(true)
    setError(null)
    try {
      const result = await gqlQuery<RiskyResult>(RISKY_COMPONENTS_QUERY, {
        search: debouncedSearch || null,
        ecosystems: ecosystem ? [ecosystem] : null,
        page,
        perPage: PER_PAGE,
      })
      if (fetchSeqRef.current !== seq) return // superseded by a newer fetch
      setData(result.sbom.riskyComponents)
    } catch (e) {
      if (fetchSeqRef.current !== seq) return
      setError(e instanceof Error ? e.message : "Failed to load risky components")
    } finally {
      if (fetchSeqRef.current === seq) setLoading(false)
    }
  }, [debouncedSearch, ecosystem, page])

  // A package name can appear as more than one ecosystem row, so the expand
  // state is keyed by (name, ecosystem) and the drill-down is fetched scoped to
  // that ecosystem, so its asset list reconciles with the row's blast-radius.
  async function togglePackageRepos(rowKey: string, packageName: string, ecosystem: string) {
    if (expandedPkg === rowKey) {
      setExpandedPkg(null)
      pkgReqRef.current = null
      return
    }
    setExpandedPkg(rowKey)
    pkgReqRef.current = rowKey
    setPkgRepos([])
    setPkgReposLoading(true)
    try {
      const r = await gqlQuery<{ sbom: { packageRepos: PackageRepo[] } }>(
        PACKAGE_REPOS_QUERY,
        { packageName, ecosystem },
      )
      if (pkgReqRef.current !== rowKey) return
      setPkgRepos(r.sbom.packageRepos)
    } catch {
      if (pkgReqRef.current === rowKey) setPkgRepos([])
    } finally {
      if (pkgReqRef.current === rowKey) setPkgReposLoading(false)
    }
  }

  useEffect(() => {
    void fetchData()
  }, [fetchData])

  const total = data?.total ?? 0
  const totalPages = data?.totalPages ?? 0
  const hasFilters = debouncedSearch !== "" || ecosystem !== ""

  function resetFilters() {
    setSearch("")
    setDebouncedSearch("")
    setEcosystem("")
    setPage(1)
  }

  const riskyAttributes: AttributeDef[] = [
    {
      key: "ecosystem",
      label: "ecosystem",
      group: "Package",
      description: "Package ecosystem",
      type: "enum",
      options: ecosystems.map((e) => ({ value: e, label: e })),
    },
  ]

  return (
    <div className="space-y-4">
      <p className="max-w-prose text-sm text-[var(--color-text-secondary)]">
        One row per package across all repositories and container images, ranked by risk.
      </p>

      {/* Faceted command bar — same search pattern as the Findings tab */}
      <CommandBar
        attributes={riskyAttributes}
        values={{ ecosystem: ecosystem || null }}
        onChange={(key, value) => {
          if (key === "ecosystem") {
            setEcosystem(value ?? "")
            setPage(1)
          }
        }}
        searchInput={search}
        onSearchInputChange={setSearch}
        searchPlaceholder="Search packages…"
      />

      <div className="flex items-center justify-between">
        {(data || loading) && (
          <span className="text-xs tabular-nums text-[var(--color-text-secondary)]">
            {loading
              ? "Loading…"
              : `${total.toLocaleString()} package${total !== 1 ? "s" : ""} · ranked by risk`}
          </span>
        )}
        {hasFilters && (
          <Button variant="ghost" size="xs" onClick={resetFilters}>
            Clear all
          </Button>
        )}
      </div>

      {error && (
        <div
          role="alert"
          className="flex items-center justify-between gap-3 rounded-md border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3"
        >
          <p className="text-sm text-[var(--color-severity-critical-text)]">{error}</p>
          <Button variant="secondary" size="sm" onClick={() => void fetchData()}>
            Retry
          </Button>
        </div>
      )}

      {/* Keep the last results mounted through a transient refetch error (the
          banner above explains it) rather than blanking the whole table. */}
      {(data || loading) && (
        <Card padding="none" className="overflow-hidden rounded-md">
          <div
            className={`overflow-x-auto transition-opacity ${loading && data ? "opacity-60" : ""}`}
            aria-busy={loading || undefined}
          >
            <Table>
              <Thead>
                <Tr>
                  <Th>Package</Th>
                  <Th className="w-64">Severity</Th>
                  <Th className="w-40 text-right" title="Repositories and container images with an open vulnerability in this package">Affected assets</Th>
                </Tr>
              </Thead>
              <Tbody>
                {loading && !data ? (
                  Array.from({ length: 8 }).map((_, i) => (
                    <Tr key={i}>
                      {Array.from({ length: 3 }).map((_, j) => (
                        <Td key={j}>
                          <Skeleton className="h-4" style={{ width: `${j === 0 ? 55 : 40}%` }} />
                        </Td>
                      ))}
                    </Tr>
                  ))
                ) : data && data.items.length === 0 ? (
                  <Tr>
                    <Td colSpan={3} className="px-4 py-12 text-center">
                      <p className="text-sm text-[var(--color-text-secondary)]">
                        {hasFilters
                          ? "No risky packages match your filters."
                          : "No packages with open dependency vulnerabilities."}
                      </p>
                      {!hasFilters && (
                        <p className="mx-auto mt-1 max-w-sm text-xs text-[var(--color-text-tertiary)]">
                          Packages appear here once dependency scans have run and any vulnerabilities are matched. That doesn&apos;t necessarily mean your estate is clean.
                        </p>
                      )}
                      {hasFilters && (
                        <div className="mt-3">
                          <Button variant="secondary" size="sm" onClick={resetFilters}>
                            Clear filters
                          </Button>
                        </div>
                      )}
                    </Td>
                  </Tr>
                ) : (
                  data?.items.map((c) => (
                    <Fragment key={rowKey(c)}>
                      <Tr>
                        <Td>
                          <div className="flex flex-col gap-0.5">
                            <span className="font-medium text-[var(--color-text-primary)]">
                              {c.packageName}
                            </span>
                            <div className="flex items-center gap-2">
                              {c.ecosystem && (
                                <span className="text-2xs font-mono uppercase tracking-[0.12em] text-[var(--color-text-secondary)]">
                                  {c.ecosystem}
                                </span>
                              )}
                              {(c.license || c.licenseCategory) && (
                                <ComponentLicenseBadge spdxId={c.license} category={c.licenseCategory} />
                              )}
                            </div>
                          </div>
                        </Td>
                        <Td>
                          <SeverityBreakdown vulns={c.vulns} packageName={c.packageName} showTotal />
                        </Td>
                        <Td className="text-right">
                          <button
                            type="button"
                            onClick={() => togglePackageRepos(rowKey(c), c.packageName, c.ecosystem)}
                            aria-expanded={expandedPkg === rowKey(c)}
                            aria-label={`Show the ${c.repoCount} affected asset${c.repoCount !== 1 ? "s" : ""}`}
                            title={`Show the ${c.repoCount} affected asset${c.repoCount !== 1 ? "s" : ""}`}
                            className="inline-flex items-center gap-1.5 tabular-nums text-sm font-medium text-[var(--color-text-primary)] transition-colors hover:text-[var(--color-accent)] focus-visible:rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
                          >
                            {c.repoCount.toLocaleString()}
                            <svg className={`h-3 w-3 text-[var(--color-text-secondary)] transition-transform ${expandedPkg === rowKey(c) ? "rotate-180" : ""}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                              <path d="m6 9 6 6 6-6" />
                            </svg>
                          </button>
                        </Td>
                      </Tr>

                      {expandedPkg === rowKey(c) && (
                        <Tr>
                          <Td colSpan={3} className="bg-[var(--color-bg)] px-4 py-0">
                            <div className="py-3 pl-6">
                              <p className="mb-2 text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                                Affected assets
                              </p>
                              {pkgReposLoading ? (
                                <div className="space-y-2">
                                  {[1, 2].map((i) => <Skeleton key={i} className="h-4 w-64" />)}
                                </div>
                              ) : pkgRepos.length === 0 ? (
                                <p className="text-xs text-[var(--color-text-secondary)]">No assets found.</p>
                              ) : (
                                <div className="space-y-1">
                                  {pkgRepos.map((r) => (
                                    <div key={`${r.org}:${r.repo}`} className="flex items-center gap-3 rounded-md px-3 py-1.5 text-xs transition-colors hover:bg-[var(--color-surface-raised)]">
                                      {r.isContainer ? (
                                        <span className="font-medium text-[var(--color-text-primary)]">{r.repo}</span>
                                      ) : (
                                        <Link href={`/sbom/${encodeURIComponent(r.repo)}`} className="font-medium text-[var(--color-text-primary)] hover:text-[var(--color-accent)]">
                                          {r.repo}
                                        </Link>
                                      )}
                                      <SourceBadge isContainer={r.isContainer} />
                                      <span className="ml-auto">
                                        <SeverityBreakdown vulns={r.vulns} packageName={c.packageName} repo={r.isContainer ? undefined : r.repo} />
                                      </span>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </Td>
                        </Tr>
                      )}
                    </Fragment>
                  ))
                )}
              </Tbody>
            </Table>
          </div>

          {totalPages > 1 && (
            <PaginatedTableFooter
              totalCount={total}
              page={page}
              perPage={PER_PAGE}
              totalPages={totalPages}
              onPageChange={setPage}
              onPerPageChange={() => {}}
              label="packages"
            />
          )}
        </Card>
      )}
    </div>
  )
}
