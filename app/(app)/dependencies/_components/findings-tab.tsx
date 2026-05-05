"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import type { DependenciesFinding } from "@/lib/shared/dependencies/types"
import type { GqlDependenciesFindingsConnection, GqlFilterOptions, GqlPageInfo } from "@/lib/shared/graphql/types"
import { findingIdentityKey } from "@/lib/shared/dependencies/utils"
import { visibleFindingKey } from "@/lib/shared/visible-alerts"
import { FindingsSearchBar } from "@/app/(app)/dependencies/_components/findings-search-bar"
import { FindingsTable } from "@/app/(app)/dependencies/_components/findings-table"
import { DependenciesAlertDrawer } from "@/app/(app)/dependencies/_components/dependencies-alert-drawer"
import { DISMISS_REASONS } from "@/lib/shared/dependencies/utils"
import { aggregateFindings } from "@/app/(app)/dependencies/_components/findings-row"
import { DEPENDENCIES_VIEW_MODES, type ViewMode } from "@/components/shared/ViewModeToggle"

type BulkReviewFn = (org: string, identityKeys: string[], action: "dismiss" | "reopen", reason?: string) => Promise<unknown>
type DismissFn = (org: string, identityKey: string, reason: string) => Promise<unknown>
type ReopenFn = (org: string, identityKey: string) => Promise<unknown>

/**
 * Adapt a GqlDependenciesFinding to the DependenciesFinding shape needed by the table/drawer.
 * This is a lightweight shim until table components are fully migrated.
 */
function gqlToDependenciesFinding(gql: GqlDependenciesFindingsConnection["items"][number]): DependenciesFinding {
  const repoName = gql.repoFullName.includes("/")
    ? gql.repoFullName.split("/").pop()!
    : gql.repoFullName
  return {
    id: gql.id,
    number: 0,
    url: "",
    html_url: "",
    state: gql.state as DependenciesFinding["state"],
    created_at: gql.firstSeenAt ?? new Date().toISOString(),
    updated_at: gql.firstSeenAt ?? new Date().toISOString(),
    fixed_at: gql.fixedAt ?? undefined,
    dismissed_at: null,
    dismissed_by: null,
    dismissed_reason: null,
    dismissed_comment: null,
    security_advisory: {
      ghsa_id: gql.id,
      cve_id: null,
      severity: gql.severity as any,
      summary: gql.advisorySummary ?? "",
      description: "",
      cvss: { score: gql.cvssScore ?? null, vector_string: null },
      published_at: gql.firstSeenAt ?? "",
      updated_at: gql.firstSeenAt ?? "",
      references: [],
    },
    current_version: gql.currentVersion ?? undefined,
    dependency: {
      package: {
        name: gql.packageName,
        ecosystem: gql.ecosystem,
      },
      manifest_path: gql.manifestPath ?? "",
      scope: null,
    },
    security_vulnerability: {
      package: { ecosystem: gql.ecosystem, name: gql.packageName },
      severity: gql.severity as any,
      vulnerable_version_range: gql.vulnerableVersion,
      first_patched_version: gql.patchedVersion ? { identifier: gql.patchedVersion } : null,
    },
    repository: {
      id: 0,
      name: repoName,
      full_name: gql.repoFullName,
    },
  } as unknown as DependenciesFinding
}

export function DependenciesFindingsTab({
  gqlFindings,
  filterOptions,
  findingsPage = 1,
  findingsPerPage = 50,
  onPageChange,
  onPerPageChange,
  stateFilter,
  severityFilter,
  ecosystemFilter = [],
  packageSearchFilter = "",
  repositoryFilter = "",
  organizationFilter = "",
  fixAvailabilityFilter = "",
  cvssRangeFilter = "",
  newSinceLastScan = false,
  lastScanDate,
  ageBucketFilter = "",
  org,
  onStateFilterChange,
  onSeverityFilterChange,
  onEcosystemFilterChange,
  onRepositoryFilterChange,
  onOrganizationFilterChange,
  onFixAvailabilityFilterChange,
  onCvssRangeFilterChange,
  onNewSinceLastScanChange,
  onAgeBucketFilterChange,
  onResetFilters,
  onFindingStateChange,
  bulkReviewFn,
  dismissFn,
  reopenFn,
  viewMode = "list",
  viewModes: viewModesProp,
  onViewModeChange,
}: {
  gqlFindings: GqlDependenciesFindingsConnection | null
  filterOptions: GqlFilterOptions | null
  findingsPage?: number
  findingsPerPage?: number
  onPageChange?: (page: number) => void
  onPerPageChange?: (perPage: number) => void
  stateFilter: string
  severityFilter: string[]
  ecosystemFilter?: string[]
  packageSearchFilter?: string
  repositoryFilter?: string
  organizationFilter?: string
  fixAvailabilityFilter?: string
  cvssRangeFilter?: string
  newSinceLastScan?: boolean
  lastScanDate?: string | null
  ageBucketFilter?: string
  org: string
  onStateFilterChange: (v: string) => void
  onSeverityFilterChange: (v: string[]) => void
  onEcosystemFilterChange?: (v: string[]) => void
  onRepositoryFilterChange?: (v: string) => void
  onOrganizationFilterChange?: (v: string) => void
  onFixAvailabilityFilterChange?: (v: string) => void
  onCvssRangeFilterChange?: (v: string) => void
  onNewSinceLastScanChange?: (v: boolean) => void
  onAgeBucketFilterChange?: (v: string) => void
  onResetFilters: () => void
  onFindingStateChange?: () => void
  bulkReviewFn: BulkReviewFn
  dismissFn?: DismissFn
  reopenFn?: ReopenFn
  viewMode?: string
  viewModes?: ViewMode[]
  onViewModeChange?: (mode: string) => void
}) {
  const [search, setSearch]                                   = useState("")
  const [selectedFinding, setSelectedFinding]                  = useState<DependenciesFinding | null>(null)
  const [checkedKeys, setCheckedKeys]                         = useState<Set<string>>(new Set())
  const [bulkDismissOpen, setBulkDismissOpen]                 = useState(false)
  const [bulkLoading, setBulkLoading]                         = useState(false)
  const [bulkError, setBulkError]                             = useState<string | null>(null)

  // Convert GQL findings to legacy format for table/drawer
  const findings: DependenciesFinding[] = useMemo(
    () => (gqlFindings?.items ?? []).map(gqlToDependenciesFinding),
    [gqlFindings]
  )

  // Use filter options from GraphQL for dropdown values
  const uniqueEcosystems = useMemo(
    () => filterOptions?.ecosystems ?? [],
    [filterOptions]
  )
  const uniqueRepositories = useMemo(
    () => filterOptions?.repositories ?? [],
    [filterOptions]
  )
  const uniqueOrganizations = useMemo(
    () => filterOptions?.organizations ?? [],
    [filterOptions]
  )

  const hasActiveFilters = Boolean(search || stateFilter || severityFilter.length || ecosystemFilter.length || packageSearchFilter || repositoryFilter || organizationFilter || fixAvailabilityFilter || cvssRangeFilter || newSinceLastScan || ageBucketFilter)
  const selectedKey      = selectedFinding ? visibleFindingKey(selectedFinding) : null

  // Find all manifest variants for the selected finding (same GHSA + package + repo)
  const relatedFindings = useMemo(() => {
    if (!selectedFinding) return []
    const ghsa = selectedFinding.security_advisory.ghsa_id
    const pkg = selectedFinding.dependency.package.name
    const repo = selectedFinding.repository.name
    return findings.filter((f) =>
      f.security_advisory.ghsa_id === ghsa &&
      f.dependency.package.name === pkg &&
      f.repository.name === repo
    )
  }, [selectedFinding, findings])

  const viewModeCounts = undefined

  function handleReset() {
    setSearch("")
    onResetFilters()
  }

  function handleSelectFinding(alert: DependenciesFinding) {
    setSelectedFinding(alert)
  }

  function handleClose() {
    setSelectedFinding(null)
  }

  // Clear selection when filters change
  const filterKey = `${search}|${stateFilter}|${severityFilter.join(",")}|${ecosystemFilter.join(",")}|${packageSearchFilter}|${repositoryFilter}|${organizationFilter}|${fixAvailabilityFilter}|${cvssRangeFilter}|${newSinceLastScan}|${ageBucketFilter}`
  const prevFilterKey = useRef(filterKey)
  useEffect(() => {
    if (prevFilterKey.current !== filterKey) {
      prevFilterKey.current = filterKey
      setCheckedKeys(new Set())
      setBulkDismissOpen(false)
    }
  }, [filterKey])

  // Build a lookup from visibleFindingKey -> identityKey for checked findings
  function resolveIdentityKeys(): string[] {
    const keys: string[] = []
    for (const f of findings) {
      if (checkedKeys.has(visibleFindingKey(f))) {
        keys.push(findingIdentityKey(f))
      }
    }
    return keys
  }

  async function handleBulkDismiss(reason: string) {
    const identityKeys = resolveIdentityKeys()
    if (identityKeys.length === 0) return
    setBulkLoading(true)
    setBulkError(null)
    try {
      await bulkReviewFn(org, identityKeys, "dismiss", reason)
      setCheckedKeys(new Set())
      setBulkDismissOpen(false)
      onFindingStateChange?.()
    } catch {
      setBulkError("Failed to dismiss findings. Please try again.")
    } finally {
      setBulkLoading(false)
    }
  }

  async function handleBulkReopen() {
    const identityKeys = resolveIdentityKeys()
    if (identityKeys.length === 0) return
    setBulkLoading(true)
    setBulkError(null)
    try {
      await bulkReviewFn(org, identityKeys, "reopen")
      setCheckedKeys(new Set())
      onFindingStateChange?.()
    } catch {
      setBulkError("Failed to reopen findings. Please try again.")
    } finally {
      setBulkLoading(false)
    }
  }

  const pageInfo = gqlFindings?.pageInfo
  const totalCount = gqlFindings?.totalCount ?? 0

  return (
    <div className="relative">
      {/* Mobile backdrop */}
      {selectedFinding && (
        <>
          <div
            className="fixed inset-0 z-30 bg-black/20 xl:hidden"
            onClick={handleClose}
          />
          <div
            className="fixed inset-0 z-30 hidden xl:block"
            onClick={handleClose}
          />
        </>
      )}

      <div className="rounded-[20px] border border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden">
        <FindingsSearchBar
          search={search}
          stateFilter={stateFilter}
          severityFilter={severityFilter}
          ecosystemFilter={ecosystemFilter}
          repositoryFilter={repositoryFilter}
          organizationFilter={organizationFilter}
          fixAvailabilityFilter={fixAvailabilityFilter}
          cvssRangeFilter={cvssRangeFilter}
          newSinceLastScan={newSinceLastScan}
          ageBucketFilter={ageBucketFilter}
          ecosystems={uniqueEcosystems}
          repositories={uniqueRepositories}
          organizations={uniqueOrganizations}
          hasActiveFilters={hasActiveFilters}
          onSearchChange={setSearch}
          onStateFilterChange={onStateFilterChange}
          onSeverityFilterChange={onSeverityFilterChange}
          onEcosystemFilterChange={onEcosystemFilterChange ?? (() => {})}
          onRepositoryFilterChange={onRepositoryFilterChange ?? (() => {})}
          onOrganizationFilterChange={onOrganizationFilterChange ?? (() => {})}
          onFixAvailabilityFilterChange={onFixAvailabilityFilterChange ?? (() => {})}
          onCvssRangeFilterChange={onCvssRangeFilterChange ?? (() => {})}
          onNewSinceLastScanChange={onNewSinceLastScanChange ?? (() => {})}
          onAgeBucketFilterChange={onAgeBucketFilterChange ?? (() => {})}
          onResetFilters={handleReset}
          viewMode={viewMode}
          viewModes={viewModesProp ?? DEPENDENCIES_VIEW_MODES}
          viewModeCounts={viewModeCounts}
          onViewModeChange={onViewModeChange ?? (() => {})}
        />
        {checkedKeys.size > 0 && (
          <div className="flex items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-2">
            <span className="text-sm font-medium text-[var(--color-text-primary)]">
              {checkedKeys.size} selected
            </span>
            <div className="relative">
              <button
                type="button"
                onClick={() => setBulkDismissOpen(!bulkDismissOpen)}
                disabled={bulkLoading}
                className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface)] disabled:opacity-50"
              >
                Dismiss selected
              </button>
              {bulkDismissOpen && (
                <div className="absolute left-0 top-full z-10 mt-1 w-64 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-2 shadow-lg">
                  <p className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
                    Select reason
                  </p>
                  {DISMISS_REASONS.map((reason) => (
                    <button
                      key={reason}
                      type="button"
                      onClick={() => void handleBulkDismiss(reason)}
                      disabled={bulkLoading}
                      className="w-full rounded-lg px-2 py-1.5 text-left text-sm text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)] disabled:opacity-50"
                    >
                      {reason}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <button
              type="button"
              onClick={() => void handleBulkReopen()}
              disabled={bulkLoading}
              className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface)] disabled:opacity-50"
            >
              Reopen selected
            </button>
            <button
              type="button"
              onClick={() => { setCheckedKeys(new Set()); setBulkDismissOpen(false) }}
              className="rounded-lg px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            >
              Clear
            </button>
            {bulkError && (
              <span className="text-xs text-red-400">{bulkError}</span>
            )}
          </div>
        )}
        <FindingsTable
          findings={aggregateFindings(
            findings,
            viewMode === "repository"
              ? (f) => f.dependency.package.name
              : viewMode === "package"
                ? (f) => f.repository.name
                : (f) => f.repository.name,
          )}
          selectedFindingKey={selectedKey}
          onSelectFinding={handleSelectFinding}
          checkedKeys={checkedKeys}
          onCheckedKeysChange={setCheckedKeys}
          serverPage={findingsPage}
          serverPerPage={findingsPerPage}
          serverTotalCount={totalCount}
          serverTotalPages={pageInfo?.totalPages ?? 1}
          onServerPageChange={onPageChange}
          onServerPerPageChange={onPerPageChange}
          groupBy={
            viewMode === "repository"
              ? (a) => a.representative.repository.full_name
              : viewMode === "package"
                ? (a) => a.representative.dependency.package.name
                : undefined
          }
          renderGroupLabel={
            viewMode === "repository"
              ? (label) => {
                  const slash = label.indexOf("/")
                  if (slash === -1) return label
                  return (
                    <>
                      <span className="font-normal text-[var(--color-text-secondary)]">{label.slice(0, slash)}</span>
                      <span className="font-normal text-[var(--color-text-secondary)]"> / </span>
                      {label.slice(slash + 1)}
                    </>
                  )
                }
              : undefined
          }
          hideColumns={
            viewMode === "repository"
              ? new Set(["organization", "repository"])
              : viewMode === "package"
                ? new Set(["package"])
                : undefined
          }
        />
      </div>

      <DependenciesAlertDrawer
        finding={selectedFinding}
        relatedFindings={relatedFindings}
        org={org}
        onClose={handleClose}
        onStateChange={onFindingStateChange}
        dismissFn={dismissFn}
        reopenFn={reopenFn}
      />

    </div>
  )
}
