import { CodePreviewPanel } from "@/app/(app)/secrets/_components/code-preview-panel"
import { ReviewSearchBar } from "@/app/(app)/secrets/_components/review-search-bar"
import { RepoGroupedFindings, type SecretFindingRow } from "@/app/(app)/secrets/_components/repo-grouped-findings"
import type { ViewMode } from "@/components/shared/ViewModeToggle"
import type { CodePreviewResponse } from "@/lib/client/secrets/dashboard-client"
import type { SecretFinding, SecretReviewStatus } from "@/lib/shared/secrets/types"

export function ReviewTab({
  sortedRows,
  selected,
  activeFinding,
  codePreview,
  correlatedFindings,
  isLoadingPreview,
  previewError,
  search,
  organization,
  repository,
  statusFilter,
  keyType,
  ageBucket,
  newFindings,
  classificationFilter,
  sortOrder,
  organizations,
  repositories,
  keyTypes,
  hasActiveFilters,
  onSearchChange,
  onOrganizationChange,
  onRepositoryChange,
  onStatusFilterChange,
  onKeyTypeChange,
  onAgeBucketChange,
  onNewFindingsChange,
  onClassificationFilterChange,
  onClassificationFilterClear,
  onSortOrderChange,
  onResetFilters,
  onBulkReview,
  onPreview,
  onToggleSelect,
  onSetSelected,
  onReview,
  onClosePreview,
  canReview,
  viewMode,
  viewModes,
  onViewModeChange,
  serverPage,
  serverPerPage,
  serverTotalCount,
  serverTotalPages,
  onServerPageChange,
  onServerPerPageChange,
}: {
  sortedRows: SecretFindingRow[]
  selected: Set<string>
  activeFinding: SecretFinding | null
  codePreview: CodePreviewResponse | null
  correlatedFindings: SecretFinding[]
  isLoadingPreview: boolean
  previewError: string | null
  search: string
  organization: string
  repository: string
  statusFilter: string
  keyType: string[]
  ageBucket: string
  newFindings: boolean
  classificationFilter: string[]
  sortOrder: string
  organizations: string[]
  repositories: string[]
  keyTypes: string[]
  hasActiveFilters: boolean
  onSearchChange: (value: string) => void
  onOrganizationChange: (value: string) => void
  onRepositoryChange: (value: string) => void
  onStatusFilterChange: (value: string) => void
  onKeyTypeChange: (value: string) => void
  onAgeBucketChange: (value: string) => void
  onNewFindingsChange: (value: boolean) => void
  onClassificationFilterChange: (value: string) => void
  onClassificationFilterClear: () => void
  onSortOrderChange: (value: string) => void
  onResetFilters: () => void
  onBulkReview: (status: SecretReviewStatus) => void
  onPreview: (finding: SecretFinding) => void
  onToggleSelect: (key: string) => void
  onSetSelected: (keys: string[], shouldSelect: boolean) => void
  onReview: (status: SecretReviewStatus, findings?: SecretFinding[]) => void
  onClosePreview: () => void
  canReview?: boolean
  viewMode?: string
  viewModes?: ViewMode[]
  onViewModeChange?: (mode: string) => void
  serverPage?: number
  serverPerPage?: number
  serverTotalCount?: number
  serverTotalPages?: number
  onServerPageChange?: (page: number) => void
  onServerPerPageChange?: (perPage: number) => void
}) {
  return (
    <div className="relative">
      {/* Backdrop — dark on mobile, transparent on desktop; clicking it closes the drawer */}
      {activeFinding !== null && (
        <div
          className="fixed inset-0 z-30 bg-black/20 xl:bg-transparent"
          onClick={onClosePreview}
          aria-hidden="true"
        />
      )}

      {/* Code Preview Drawer — fixed overlay, slides in from right */}
      <CodePreviewPanel
        finding={activeFinding}
        preview={codePreview}
        relatedFindings={correlatedFindings}
        isLoading={isLoadingPreview}
        error={previewError}
        canReview={canReview}
        onSelectRelated={onPreview}
        onReview={(status) => onReview(status, activeFinding ? [activeFinding] : undefined)}
        onClose={onClosePreview}
      />

      {/* Full-width findings table */}
      <div className="overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">
        <ReviewSearchBar
          search={search}
          statusFilter={statusFilter}
          repository={repository}
          organization={organization}
          keyType={keyType}
          ageBucket={ageBucket}
          newFindings={newFindings}
          sortOrder={sortOrder}
          organizations={organizations}
          repositories={repositories}
          keyTypes={keyTypes}
          hasActiveFilters={hasActiveFilters}
          selectedCount={selected.size}
          canReview={canReview}
          onSearchChange={onSearchChange}
          onStatusFilterChange={onStatusFilterChange}
          onRepositoryChange={onRepositoryChange}
          onOrganizationChange={onOrganizationChange}
          onKeyTypeChange={onKeyTypeChange}
          onAgeBucketChange={onAgeBucketChange}
          onNewFindingsChange={onNewFindingsChange}
          classificationFilter={classificationFilter}
          onClassificationFilterChange={onClassificationFilterChange}
          onClassificationFilterClear={onClassificationFilterClear}
          onSortOrderChange={onSortOrderChange}
          onResetFilters={onResetFilters}
          onBulkReview={onBulkReview}
          viewMode={viewMode}
          viewModes={viewModes}
          onViewModeChange={onViewModeChange}
        />
        <RepoGroupedFindings
          rows={sortedRows}
          selected={selected}
          activeFinding={activeFinding}
          onToggleSelect={onToggleSelect}
          onSetSelected={onSetSelected}
          onSelectFinding={onPreview}
          totalCount={sortedRows.length}
          serverPage={serverPage}
          serverPerPage={serverPerPage}
          serverTotalCount={serverTotalCount}
          serverTotalPages={serverTotalPages}
          onServerPageChange={onServerPageChange}
          onServerPerPageChange={onServerPerPageChange}
          groupBy={
            viewMode === "repository"
              ? (row) => `${row.finding.organization}/${row.finding.repository}`
              : viewMode === "key"
              ? (row) => row.finding.detector || "Unknown"
              : undefined
          }
          groupLabel={
            viewMode === "repository" ? "repos" : viewMode === "key" ? "key types" : undefined
          }
          hideColumns={
            viewMode === "repository"
              ? new Set(["repository"])
              : viewMode === "key"
              ? new Set(["detector"])
              : undefined
          }
        />
      </div>
    </div>
  )
}
