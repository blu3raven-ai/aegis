"use client"

import { ViewModeToggle, CODE_SCANNING_VIEW_MODES } from "@/components/shared/ViewModeToggle"
import { FilterTag } from "@/components/shared/FilterTag"
import { SearchInput } from "@/components/shared/SearchInput"
import { ToggleChip } from "@/components/shared/ToggleChip"
import { SelectFilter } from "@/components/shared/SelectFilter"

const SEVERITIES = ["critical", "high", "medium", "low"] as const

interface Props {
  search: string
  filterState: string
  filterSeverity: string[]
  filterRepoExact: string
  filterLanguage: string
  filterReachability: string
  filterConfidence: string
  filterNewFindings: boolean
  filterRuleId: string
  filterAgeBucket: string
  viewMode: string
  repos: string[]
  languages: string[]
  hasActiveFilters: boolean
  onSearchChange: (v: string) => void
  onFilterStateChange: (v: string) => void
  onFilterSeverityChange: (v: string[]) => void
  onFilterRepoExactChange: (v: string) => void
  onFilterLanguageChange: (v: string) => void
  onFilterReachabilityChange: (v: string) => void
  onFilterConfidenceChange: (v: string) => void
  onFilterNewFindingsChange: (v: boolean) => void
  onFilterRuleIdChange: (v: string) => void
  onFilterAgeBucketChange: (v: string) => void
  onViewModeChange: (v: string) => void
  onResetFilters: () => void
}

export function CodeScanningFindingsSearchBar({
  search,
  filterState,
  filterSeverity,
  filterRepoExact,
  filterLanguage,
  filterReachability,
  filterConfidence,
  filterNewFindings,
  filterRuleId,
  filterAgeBucket,
  viewMode,
  repos,
  languages,
  hasActiveFilters,
  onSearchChange,
  onFilterStateChange,
  onFilterSeverityChange,
  onFilterRepoExactChange,
  onFilterLanguageChange,
  onFilterReachabilityChange,
  onFilterConfidenceChange,
  onFilterNewFindingsChange,
  onFilterRuleIdChange,
  onFilterAgeBucketChange,
  onViewModeChange,
  onResetFilters,
}: Props) {
  function toggleSeverity(sev: string) {
    if (filterSeverity.includes(sev)) {
      onFilterSeverityChange(filterSeverity.filter((s) => s !== sev))
    } else {
      onFilterSeverityChange([...filterSeverity, sev])
    }
  }

  return (
    <div className="space-y-3 border-b border-[var(--color-border)] p-4">
      <SearchInput value={search} onChange={onSearchChange} placeholder="Search by repo, rule, or file path..." />

      {/* Filter strip */}
      <div className="flex items-start gap-2">
        <div className="flex flex-1 flex-wrap items-center gap-2">
          <SelectFilter value={filterState} onChange={onFilterStateChange}>
            <option value="">All states</option>
            <option value="open">Open</option>
            <option value="dismissed">Dismissed</option>
            <option value="fixed">Fixed</option>
            <option value="awaiting_fix">Awaiting Fix</option>
          </SelectFilter>

          <SelectFilter value={filterRepoExact} onChange={onFilterRepoExactChange}>
            <option value="">All repositories</option>
            {repos.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </SelectFilter>

          {languages.length > 0 && (
            <SelectFilter value={filterLanguage} onChange={onFilterLanguageChange}>
              <option value="">All languages</option>
              {languages.map((l) => (
                <option key={l} value={l}>{l}</option>
              ))}
            </SelectFilter>
          )}

          <SelectFilter value={filterReachability} onChange={onFilterReachabilityChange}>
            <option value="">All reachability</option>
            <option value="reachable">Reachable</option>
            <option value="unreachable">Unreachable</option>
            <option value="unknown">Unknown</option>
          </SelectFilter>

          <SelectFilter value={filterConfidence} onChange={onFilterConfidenceChange}>
            <option value="">All confidence</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </SelectFilter>

          <ToggleChip label="New findings" active={filterNewFindings} onClick={() => onFilterNewFindingsChange(!filterNewFindings)} activeColor="emerald" />
        </div>
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

      {/* Severity chips + view mode toggle */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter by severity">
          <span className="text-xs font-medium text-[var(--color-text-secondary)]">Severity:</span>
          {SEVERITIES.map((sev) => (
            <ToggleChip key={sev} label={sev} active={filterSeverity.includes(sev)} onClick={() => toggleSeverity(sev)} />
          ))}
        </div>
        <div className="ml-auto">
          <ViewModeToggle modes={CODE_SCANNING_VIEW_MODES} active={viewMode} onChange={onViewModeChange} />
        </div>
      </div>

      {/* Active filter tags */}
      {(filterState || filterRepoExact || filterLanguage || filterReachability || filterConfidence || filterRuleId || filterAgeBucket || filterNewFindings) && (
        <div className="flex flex-wrap items-center gap-2">
          {filterState && <FilterTag label={`State: ${filterState}`} onClear={() => onFilterStateChange("")} />}
          {filterRepoExact && <FilterTag label={`Repo: ${filterRepoExact}`} onClear={() => onFilterRepoExactChange("")} />}
          {filterLanguage && <FilterTag label={`Language: ${filterLanguage}`} onClear={() => onFilterLanguageChange("")} />}
          {filterReachability && <FilterTag label={`Reachability: ${filterReachability}`} onClear={() => onFilterReachabilityChange("")} />}
          {filterConfidence && <FilterTag label={`Confidence: ${filterConfidence}`} onClear={() => onFilterConfidenceChange("")} />}
          {filterRuleId && <FilterTag label={`Rule: ${filterRuleId.split(".").slice(-2).join(".")}`} onClear={() => onFilterRuleIdChange("")} />}
          {filterAgeBucket && <FilterTag label={`Age: ${filterAgeBucket}`} onClear={() => onFilterAgeBucketChange("")} color="emerald" />}
          {filterNewFindings && <FilterTag label="New findings" onClear={() => onFilterNewFindingsChange(false)} color="emerald" />}
        </div>
      )}
    </div>
  )
}
