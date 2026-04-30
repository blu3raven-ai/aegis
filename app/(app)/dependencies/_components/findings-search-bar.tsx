"use client"

import { DEPENDENCIES_AGE_BUCKETS, CVSS_RANGE_BUCKETS } from "@/lib/shared/dependencies/utils"
import { ViewModeToggle, type ViewMode } from "@/components/shared/ViewModeToggle"
import { FilterTag } from "@/components/shared/FilterTag"
import { SearchInput } from "@/components/shared/SearchInput"
import { ToggleChip } from "@/components/shared/ToggleChip"
import { SelectFilter } from "@/components/shared/SelectFilter"

const SEVERITIES = ["critical", "high", "medium", "low"] as const

interface Props {
  search: string
  stateFilter: string
  severityFilter: string[]
  ecosystemFilter: string[]
  repositoryFilter: string
  organizationFilter: string
  fixAvailabilityFilter: string
  cvssRangeFilter: string
  newSinceLastScan: boolean
  ageBucketFilter: string
  ecosystems: string[]
  repositories: string[]
  organizations: string[]
  hasActiveFilters: boolean
  onSearchChange: (v: string) => void
  onStateFilterChange: (v: string) => void
  onSeverityFilterChange: (v: string[]) => void
  onEcosystemFilterChange: (v: string[]) => void
  onRepositoryFilterChange: (v: string) => void
  onOrganizationFilterChange: (v: string) => void
  onFixAvailabilityFilterChange: (v: string) => void
  onCvssRangeFilterChange: (v: string) => void
  onNewSinceLastScanChange: (v: boolean) => void
  onAgeBucketFilterChange: (v: string) => void
  onResetFilters: () => void
  viewMode?: string
  viewModes?: ViewMode[]
  viewModeCounts?: Record<string, number>
  onViewModeChange?: (mode: string) => void
}

export function FindingsSearchBar({
  search,
  stateFilter,
  severityFilter,
  ecosystemFilter,
  repositoryFilter,
  organizationFilter,
  fixAvailabilityFilter,
  cvssRangeFilter,
  newSinceLastScan,
  ageBucketFilter,
  ecosystems,
  repositories,
  organizations,
  hasActiveFilters,
  onSearchChange,
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
  viewMode,
  viewModes,
  viewModeCounts,
  onViewModeChange,
}: Props) {
  function toggleSeverity(sev: string) {
    if (severityFilter.includes(sev)) {
      onSeverityFilterChange(severityFilter.filter((s) => s !== sev))
    } else {
      onSeverityFilterChange([...severityFilter, sev])
    }
  }

  function toggleEcosystem(eco: string) {
    if (ecosystemFilter.includes(eco)) {
      onEcosystemFilterChange(ecosystemFilter.filter((e) => e !== eco))
    } else {
      onEcosystemFilterChange([...ecosystemFilter, eco])
    }
  }

  return (
    <div className="space-y-3 border-b border-[var(--color-border)] p-4">
      <SearchInput value={search} onChange={onSearchChange} placeholder="Search by package, repo, CVE ID, or GHSA ID..." />

      {/* Filter strip */}
      <div className="flex flex-wrap items-center gap-2">
        <SelectFilter value={stateFilter} onChange={onStateFilterChange}>
          <option value="">All states</option>
          <option value="open">Open</option>
          <option value="deferred">Deferred</option>
          <option value="fixed">Fixed</option>
          <option value="dismissed">Dismissed</option>
        </SelectFilter>

        {repositories.length > 1 && (
          <SelectFilter value={repositoryFilter} onChange={onRepositoryFilterChange}>
            <option value="">All repositories</option>
            {repositories.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </SelectFilter>
        )}

        {organizations.length > 1 && (
          <SelectFilter value={organizationFilter} onChange={onOrganizationFilterChange}>
            <option value="">All organizations</option>
            {organizations.map((o) => (
              <option key={o} value={o}>{o}</option>
            ))}
          </SelectFilter>
        )}

        <SelectFilter value={ageBucketFilter} onChange={onAgeBucketFilterChange}>
          <option value="">All ages</option>
          {DEPENDENCIES_AGE_BUCKETS.map((b) => (
            <option key={b.label} value={b.label}>{b.label}</option>
          ))}
        </SelectFilter>

        <SelectFilter value={fixAvailabilityFilter} onChange={onFixAvailabilityFilterChange}>
          <option value="">All fixes</option>
          <option value="has_fix">Has fix</option>
          <option value="no_fix">No fix</option>
        </SelectFilter>

        <SelectFilter value={cvssRangeFilter} onChange={onCvssRangeFilterChange}>
          <option value="">All CVSS</option>
          {CVSS_RANGE_BUCKETS.map((b) => (
            <option key={b.label} value={b.label}>{b.label}</option>
          ))}
        </SelectFilter>

        <ToggleChip label="New findings" active={newSinceLastScan} onClick={() => onNewSinceLastScanChange(!newSinceLastScan)} activeColor="emerald" />

        {hasActiveFilters && (
          <button
            type="button"
            onClick={onResetFilters}
            className="ml-auto text-sm text-[var(--color-text-secondary)] underline hover:text-[var(--color-text-primary)]"
          >
            Reset filters
          </button>
        )}
      </div>

      {/* Ecosystem chips */}
      {ecosystems.length > 1 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-[var(--color-text-secondary)]">Ecosystem:</span>
          {ecosystems.map((eco) => (
            <ToggleChip key={eco} label={eco} active={ecosystemFilter.includes(eco)} onClick={() => toggleEcosystem(eco)} />
          ))}
        </div>
      )}

      {/* Severity chips + view mode toggle */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-[var(--color-text-secondary)]">Severity:</span>
        {SEVERITIES.map((sev) => (
          <ToggleChip key={sev} label={sev} active={severityFilter.includes(sev)} onClick={() => toggleSeverity(sev)} />
        ))}
        {viewModes && viewMode && onViewModeChange && (
          <div className="ml-auto">
            <ViewModeToggle modes={viewModes} active={viewMode} onChange={onViewModeChange} counts={viewModeCounts} />
          </div>
        )}
      </div>

      {/* Active filter tags */}
      {(stateFilter || repositoryFilter || organizationFilter || ageBucketFilter || fixAvailabilityFilter || cvssRangeFilter || newSinceLastScan) && (
        <div className="flex flex-wrap items-center gap-2">
          {stateFilter && <FilterTag label={`State: ${stateFilter}`} onClear={() => onStateFilterChange("")} />}
          {repositoryFilter && <FilterTag label={`Repo: ${repositoryFilter}`} onClear={() => onRepositoryFilterChange("")} />}
          {organizationFilter && <FilterTag label={`Org: ${organizationFilter}`} onClear={() => onOrganizationFilterChange("")} />}
          {ageBucketFilter && <FilterTag label={`Age: ${ageBucketFilter}`} onClear={() => onAgeBucketFilterChange("")} color="emerald" />}
          {fixAvailabilityFilter && <FilterTag label={fixAvailabilityFilter === "has_fix" ? "Has fix" : "No fix"} onClear={() => onFixAvailabilityFilterChange("")} />}
          {cvssRangeFilter && <FilterTag label={`CVSS: ${cvssRangeFilter}`} onClear={() => onCvssRangeFilterChange("")} color="orange" />}
          {newSinceLastScan && <FilterTag label="New findings" onClear={() => onNewSinceLastScanChange(false)} color="emerald" />}
        </div>
      )}
    </div>
  )
}
