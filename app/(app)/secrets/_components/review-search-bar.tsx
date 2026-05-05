"use client"

import type { SecretReviewStatus } from "@/lib/shared/secrets/types"
import { ViewModeToggle, type ViewMode } from "@/components/shared/ViewModeToggle"
import { FilterTag } from "@/components/shared/FilterTag"
import { SearchInput } from "@/components/shared/SearchInput"
import { ToggleChip } from "@/components/shared/ToggleChip"
import { SelectFilter } from "@/components/shared/SelectFilter"

const CLASSIFICATION_FILTER_LABELS: Record<string, string> = {
  verified_secret: "Verified Secret",
  likely_secret: "Likely Secret",
  not_secret: "Not a Secret",
  uncertain: "Uncertain",
}

interface Props {
  search: string
  statusFilter: string
  repository: string
  organization: string
  keyType: string[]
  ageBucket: string
  newFindings: boolean
  sortOrder: string
  organizations: string[]
  repositories: string[]
  keyTypes: string[]
  hasActiveFilters: boolean
  selectedCount: number
  canReview?: boolean
  onSearchChange: (v: string) => void
  onStatusFilterChange: (v: string) => void
  onRepositoryChange: (v: string) => void
  onOrganizationChange: (v: string) => void
  onKeyTypeChange: (v: string) => void
  onAgeBucketChange: (v: string) => void
  onNewFindingsChange: (v: boolean) => void
  classificationFilter: string[]
  onClassificationFilterChange: (v: string) => void
  onClassificationFilterClear: () => void
  onSortOrderChange: (v: string) => void
  onResetFilters: () => void
  onBulkReview: (status: SecretReviewStatus) => void
  viewMode?: string
  viewModes?: ViewMode[]
  onViewModeChange?: (mode: string) => void
}

export function ReviewSearchBar({
  search,
  statusFilter,
  repository,
  organization,
  keyType,
  ageBucket,
  newFindings,
  sortOrder,
  organizations,
  repositories,
  keyTypes,
  hasActiveFilters,
  selectedCount,
  onSearchChange,
  onStatusFilterChange,
  onRepositoryChange,
  onOrganizationChange,
  onKeyTypeChange,
  onAgeBucketChange,
  onNewFindingsChange,
  classificationFilter,
  onClassificationFilterChange,
  onClassificationFilterClear,
  onSortOrderChange,
  onResetFilters,
  onBulkReview,
  canReview,
  viewMode,
  viewModes,
  onViewModeChange,
}: Props) {
  return (
    <div className="space-y-3 border-b border-[var(--color-border)] p-4">
      <SearchInput value={search} onChange={onSearchChange} placeholder="Search by repo, detector, snippet, file path..." />

      {/* Filter strip */}
      <div className="flex flex-wrap items-center gap-2">
        <SelectFilter value={statusFilter} onChange={onStatusFilterChange}>
          <option value="">All statuses</option>
          <option value="new">New</option>
          <option value="confirmed">Confirmed</option>
          <option value="false_positive">False Positive</option>
          <option value="action_taken">Action Taken</option>
        </SelectFilter>

        <SelectFilter value={repository} onChange={onRepositoryChange}>
          <option value="">All repositories</option>
          {repositories.map((repo) => (
            <option key={repo} value={repo}>{repo}</option>
          ))}
        </SelectFilter>

        <SelectFilter value={organization} onChange={onOrganizationChange}>
          <option value="">All organizations</option>
          {organizations.map((org) => (
            <option key={org} value={org}>{org}</option>
          ))}
        </SelectFilter>

        {keyType.length > 1 ? (
          <span className="flex items-center gap-1.5 rounded-lg border border-[var(--color-accent)]/40 bg-[var(--color-accent-subtle)] px-3 py-1.5 text-sm font-medium text-[var(--color-accent)]">
            {keyType.length} key types
            <button
              type="button"
              onClick={() => onKeyTypeChange("")}
              className="ml-0.5 rounded hover:text-[var(--color-accent)]/80"
              aria-label="Clear key type filter"
            >
              <svg className="h-3.5 w-3.5" viewBox="0 0 20 20" fill="currentColor">
                <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
              </svg>
            </button>
          </span>
        ) : (
          <SelectFilter value={keyType[0] ?? ""} onChange={onKeyTypeChange}>
            <option value="">All key types</option>
            {keyTypes.map((kt) => (
              <option key={kt} value={kt}>{kt}</option>
            ))}
          </SelectFilter>
        )}

        <ToggleChip label="New findings" active={newFindings} onClick={() => onNewFindingsChange(!newFindings)} activeColor="emerald" />

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

      {/* Classification chips + view toggle */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-[var(--color-text-secondary)]">Classification:</span>
        {Object.entries(CLASSIFICATION_FILTER_LABELS).map(([value, label]) => (
          <ToggleChip key={value} label={label} active={classificationFilter.includes(value)} onClick={() => onClassificationFilterChange(value)} />
        ))}
        {viewModes && viewMode && onViewModeChange && (
          <div className="ml-auto">
            <ViewModeToggle modes={viewModes} active={viewMode} onChange={onViewModeChange} />
          </div>
        )}
      </div>

      {/* Active filter tags */}
      {(statusFilter || repository || organization || (keyType.length === 1 && keyType[0]) || ageBucket || newFindings) && (
        <div className="flex flex-wrap items-center gap-2">
          {statusFilter && <FilterTag label={`Status: ${statusFilter.replace("_", " ")}`} onClear={() => onStatusFilterChange("")} />}
          {repository && <FilterTag label={`Repo: ${repository}`} onClear={() => onRepositoryChange("")} />}
          {organization && <FilterTag label={`Org: ${organization}`} onClear={() => onOrganizationChange("")} />}
          {keyType.length === 1 && keyType[0] && <FilterTag label={`Key: ${keyType[0]}`} onClear={() => onKeyTypeChange("")} />}
          {ageBucket && <FilterTag label={`Age: ${ageBucket}`} onClear={() => onAgeBucketChange("")} color="emerald" />}
          {newFindings && <FilterTag label="New findings" onClear={() => onNewFindingsChange(false)} color="emerald" />}
        </div>
      )}

      {/* Bulk action bar */}
      {canReview && (
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onBulkReview("confirmed")}
            disabled={selectedCount === 0}
            className="rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-400 disabled:opacity-50"
          >
            Confirm keys
          </button>
          <button
            type="button"
            onClick={() => onBulkReview("false_positive")}
            disabled={selectedCount === 0}
            className="rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-400 disabled:opacity-50"
          >
            False Positive
          </button>
          <button
            type="button"
            onClick={() => onBulkReview("action_taken")}
            disabled={selectedCount === 0}
            className="rounded-lg border border-blue-500/20 bg-blue-500/10 px-3 py-1.5 text-xs font-semibold text-blue-400 disabled:opacity-50"
          >
            Action Taken
          </button>
          <button
            type="button"
            onClick={() => onBulkReview("new")}
            disabled={selectedCount === 0}
            className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-primary)] disabled:opacity-50"
          >
            Reset
          </button>
          {selectedCount > 0 && (
            <span className="text-xs text-[var(--color-text-secondary)]">{selectedCount} selected</span>
          )}
        </div>
      )}
    </div>
  )
}
