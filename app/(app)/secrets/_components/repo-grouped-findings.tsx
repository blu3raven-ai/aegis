import React, { useEffect, useMemo, useRef, useState } from "react"
import type { ClassificationEntry, SecretFinding } from "@/lib/shared/secrets/types"
import { findingUiIdentity, resolveClassification, reviewStatusLabel, reviewTone } from "@/lib/shared/secrets/dashboard-utils"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"
import { FindingsEmptyState } from "@/components/shared/FindingsEmptyState"
import { CollapsibleGroupHeader } from "@/components/shared/CollapsibleGroupHeader"

const GROUPS_PER_PAGE = 20

const CLASSIFICATION_ICONS: Record<string, React.ReactNode> = {
  verified_secret: (
    <svg className="inline-block mr-1 -mt-px" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  ),
  likely_secret: (
    <svg className="inline-block mr-1 -mt-px" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3l1.9 5.8H20l-4.9 3.6 1.9 5.8L12 15l-5 3.2 1.9-5.8L4 8.8h6.1z" />
    </svg>
  ),
  not_secret: (
    <svg className="inline-block mr-1 -mt-px" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="10" />
      <line x1="15" y1="9" x2="9" y2="15" />
      <line x1="9" y1="9" x2="15" y2="15" />
    </svg>
  ),
  uncertain: (
    <svg className="inline-block mr-1 -mt-px" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="10" />
      <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
}

function ClassificationBadge({ entry }: { entry: ClassificationEntry | null | undefined }) {
  if (!entry) return null
  const styles: Record<string, string> = {
    // Current schema values
    verified_secret:
      "border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]",
    likely_secret:
      "border-[var(--color-accent)]/50 bg-transparent text-[var(--color-accent)]",
    not_secret:
      "border-[var(--color-border-strong)] bg-transparent text-[var(--color-text-tertiary)]",
    uncertain:
      "border-[var(--color-border-strong)] bg-transparent text-[var(--color-text-tertiary)]",
    // Legacy schema values
    confirmed:
      "border-[var(--color-accent)]/50 bg-transparent text-[var(--color-accent)]",
    likely_real:
      "border-[var(--color-accent)]/50 bg-transparent text-[var(--color-accent)]",
    false_positive:
      "border-[var(--color-border-strong)] bg-transparent text-[var(--color-text-tertiary)]",
  }
  const labels: Record<string, string> = {
    // Current schema values
    verified_secret: "Verified Secret",
    likely_secret: "Likely Secret",
    not_secret: "Not a Secret",
    uncertain: "Uncertain",
    // Legacy schema values
    confirmed: "Confirmed",
    likely_real: "Likely Real",
    false_positive: "False Positive",
  }
  const cls = styles[entry.value] ?? styles["uncertain"]
  const label = labels[entry.value] ?? entry.value
  const pct = entry.confidence != null && entry.confidence < 1
    ? `${(entry.confidence * 100).toFixed(0)}%`
    : null
  return (
    <span className={`shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium ${cls}`}>
      {CLASSIFICATION_ICONS[entry.value]}
      {label}
      {pct && (
        <span className="ml-1 opacity-60 tabular-nums">· {pct}</span>
      )}
    </span>
  )
}

export interface SecretFindingRow {
  finding: SecretFinding
  rowKey: string
}

interface Props {
  rows: SecretFindingRow[]
  selected: Set<string>
  activeFinding: SecretFinding | null
  onToggleSelect: (key: string) => void
  onSetSelected: (keys: string[], shouldSelect: boolean) => void
  onSelectFinding: (finding: SecretFinding) => void
  totalCount: number
  /** When set, rows are grouped under collapsible headers. When undefined, flat table. */
  groupBy?: (row: SecretFindingRow) => string
  /** Columns to hide (e.g. "repository" in repo view) */
  hideColumns?: Set<string>
  /** Label for the group unit shown in the footer (e.g. "repos", "key types") */
  groupLabel?: string
  /** Server-side pagination — when provided, overrides client-side pagination */
  serverPage?: number
  serverPerPage?: number
  serverTotalCount?: number
  serverTotalPages?: number
  onServerPageChange?: (page: number) => void
  onServerPerPageChange?: (perPage: number) => void
}

export function RepoGroupedFindings({
  rows,
  selected,
  activeFinding,
  onToggleSelect,
  onSetSelected,
  onSelectFinding,
  totalCount,
  groupBy,
  groupLabel,
  hideColumns,
  serverPage,
  serverPerPage,
  serverTotalCount,
  serverTotalPages,
  onServerPageChange,
  onServerPerPageChange,
}: Props) {
  const [expandedRepos, setExpandedRepos] = useState<Set<string>>(new Set())
  const [localPage, setLocalPage] = useState(1)
  const [localPerPage, setLocalPerPage] = useState(25)
  const [localGroupPage, setLocalGroupPage] = useState(1)

  const useServerPagination = serverPage != null && onServerPageChange != null
  const page = useServerPagination ? serverPage! : localPage
  const perPage = useServerPagination ? (serverPerPage ?? 50) : localPerPage
  const setPage = useServerPagination ? onServerPageChange! : setLocalPage
  const setPerPage = useServerPagination ? (onServerPerPageChange ?? (() => {})) : setLocalPerPage

  // Reset local page when rows change (e.g. filter change) — only in client-side mode
  const prevRowsRef = useRef(rows)
  useEffect(() => {
    if (useServerPagination) return
    if (prevRowsRef.current !== rows) {
      prevRowsRef.current = rows
      setLocalPage(1)
    }
  }, [rows, useServerPagination])

  const grouped = useMemo(() => {
    if (!groupBy) return null
    const map = new Map<string, SecretFindingRow[]>()
    for (const row of rows) {
      const key = groupBy(row)
      const existing = map.get(key) ?? []
      existing.push(row)
      map.set(key, existing)
    }
    return Array.from(map.entries()).sort((a, b) => {
      const countDiff = b[1].length - a[1].length
      if (countDiff !== 0) return countDiff
      return a[0].localeCompare(b[0])
    })
  }, [rows, groupBy])

  function toggleRepo(repo: string) {
    setExpandedRepos((current) => {
      const next = new Set(current)
      if (next.has(repo)) next.delete(repo)
      else next.add(repo)
      return next
    })
  }

  function expandAll() {
    setExpandedRepos(new Set((grouped ?? []).map(([repo]) => repo)))
  }

  function collapseAll() {
    setExpandedRepos(new Set())
  }

  // When grouped, always paginate groups client-side regardless of server mode
  const groupTotalPages = grouped ? Math.max(1, Math.ceil(grouped.length / GROUPS_PER_PAGE)) : 1
  const safeGroupPage = Math.min(Math.max(localGroupPage, 1), groupTotalPages)

  // Reset group page when groups change
  const prevGroupsLengthRef = useRef<number | null>(null)
  useEffect(() => {
    const len = grouped ? grouped.length : null
    if (prevGroupsLengthRef.current !== len) {
      prevGroupsLengthRef.current = len
      setLocalGroupPage(1)
    }
  }, [grouped])

  const totalPages = useServerPagination
    ? Math.max(1, serverTotalPages ?? 1)
    : Math.max(1, Math.ceil(rows.length / perPage))
  const safePage = Math.min(Math.max(page, 1), totalPages)
  // In server pagination mode, all rows are the current page (server already sliced)
  const pageRows = useServerPagination ? rows : rows.slice((safePage - 1) * perPage, safePage * perPage)
  const pageGroups = grouped ? grouped.slice((safeGroupPage - 1) * GROUPS_PER_PAGE, safeGroupPage * GROUPS_PER_PAGE) : null

  const allRowKeys = useMemo(() => rows.map((row) => row.rowKey), [rows])
  const selectedVisibleCount = allRowKeys.filter((key) => selected.has(key)).length
  const allVisibleSelected = allRowKeys.length > 0 && selectedVisibleCount === allRowKeys.length

  if (rows.length === 0) {
    return <FindingsEmptyState message="No findings yet. Run a scan to populate this view." />
  }

  function renderRow({ finding, rowKey }: SecretFindingRow) {
    const isActive = activeFinding && findingUiIdentity(activeFinding) === findingUiIdentity(finding)
    return (
      <tr
        key={rowKey}
        onClick={() => onSelectFinding(finding)}
        className={`cursor-pointer border-b border-[var(--color-border)] transition-colors hover:bg-[var(--color-surface-raised)] ${
          isActive ? "border-l-2 border-l-[var(--color-accent)] bg-[var(--color-accent)]/5" : ""
        }`}
      >
        <td className="w-8 px-2 py-2.5" onClick={(e) => e.stopPropagation()}>
          <input
            type="checkbox"
            checked={selected.has(rowKey)}
            onChange={() => onToggleSelect(rowKey)}
            className="cursor-pointer accent-[var(--color-accent)]"
          />
        </td>
        <td className="px-2.5 py-2.5 overflow-hidden">
          <span className={`shrink-0 whitespace-nowrap rounded-full border px-1.5 py-0.5 text-[11px] font-medium ${reviewTone(finding.reviewStatus)}`}>
            {reviewStatusLabel(finding.reviewStatus)}
          </span>
        </td>
        <td className="px-2.5 py-2.5 text-xs font-medium text-[var(--color-text-secondary)] truncate" title={finding.detector}>{finding.detector}</td>
        <td className="px-2.5 py-2.5 truncate"><ClassificationBadge entry={resolveClassification(finding.classificationHistory)} /></td>
        {!hideColumns?.has("repository") && (
          <td className="px-2.5 py-2.5 text-xs font-medium text-[var(--color-text-primary)] truncate" title={`${finding.organization}/${finding.repository}`}>
            {finding.organization}/{finding.repository}
          </td>
        )}
        <td className="px-2.5 py-2.5 truncate">
          <span className="block truncate font-mono text-[11px] text-[var(--color-text-primary)]" title={finding.secretSnippet}>
            {finding.secretSnippet}
          </span>
        </td>
        <td className="px-2.5 py-2.5 text-xs text-[var(--color-text-secondary)] truncate" title={finding.filePath ?? ""}>
          {finding.filePath ? finding.filePath.split("/").pop() : "-"}
          {finding.line ? `:${finding.line}` : ""}
        </td>
        <td className="px-2.5 py-2.5 whitespace-nowrap font-mono text-xs text-[var(--color-text-secondary)]">
          {finding.commit ? finding.commit.slice(0, 7) : "—"}
        </td>
      </tr>
    )
  }

  const thCls = "px-2.5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]"
  const colCount = 7 + (hideColumns?.has("repository") ? 0 : 1)

  return (
    <div className="overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 text-xs text-[var(--color-text-secondary)]">
        <span>
          {grouped
            ? `${grouped.length} ${groupLabel ?? "groups"}`
            : `${useServerPagination ? (serverTotalCount ?? totalCount) : totalCount} keys`}
          {selectedVisibleCount > 0 ? ` · ${selectedVisibleCount} selected` : ""}
        </span>
        <div className="flex flex-wrap justify-end gap-2">
          <button
            type="button"
            onClick={() => onSetSelected(allRowKeys, !allVisibleSelected)}
            className="rounded px-2 py-1 font-semibold text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)]"
          >
            {allVisibleSelected ? "Clear visible" : "Select all visible"}
          </button>
          {grouped && (
            <>
              <button type="button" onClick={expandAll} className="rounded px-2 py-1 hover:bg-[var(--color-surface-raised)]">
                Expand all
              </button>
              <button type="button" onClick={collapseAll} className="rounded px-2 py-1 hover:bg-[var(--color-surface-raised)]">
                Collapse all
              </button>
            </>
          )}
        </div>
      </div>

      <div>
        <table className="w-full table-fixed text-left text-sm">
          <thead className="border-b border-[var(--color-border)] bg-[var(--color-surface-raised)]">
            <tr>
              <th className="w-8 px-2 py-2.5">
                <input
                  type="checkbox"
                  className="accent-[var(--color-accent)]"
                  checked={allVisibleSelected}
                  onChange={() => onSetSelected(allRowKeys, !allVisibleSelected)}
                />
              </th>
              <th className={`${thCls} w-[110px]`}>Status</th>
              <th className={`${thCls} w-[100px]`}>Detector</th>
              <th className={`${thCls} w-[190px]`}>Classification</th>
              {!hideColumns?.has("repository") && <th className={thCls}>Repo</th>}
              <th className={thCls}>Secret</th>
              <th className={thCls}>File</th>
              <th className={`${thCls} w-[68px]`}>Commit</th>
            </tr>
          </thead>
          <tbody>
            {pageGroups ? (
              pageGroups.map(([groupKey, groupRows]) => {
                const isExpanded = expandedRepos.has(groupKey)
                const groupRowKeys = groupRows.map((r) => r.rowKey)
                const selectedGroupCount = groupRowKeys.filter((k) => selected.has(k)).length
                const allGroupSelected = groupRowKeys.length > 0 && selectedGroupCount === groupRowKeys.length
                return (
                  <React.Fragment key={groupKey}>
                    <CollapsibleGroupHeader
                      label={groupKey}
                      count={groupRows.length}
                      isExpanded={isExpanded}
                      onToggle={() => toggleRepo(groupKey)}
                      colSpan={colCount}
                      checkboxSlot={
                        <input
                          type="checkbox"
                          className="accent-[var(--color-accent)]"
                          checked={allGroupSelected}
                          onChange={() => onSetSelected(groupRowKeys, !allGroupSelected)}
                        />
                      }
                    />
                    {isExpanded && groupRows.map((row) => renderRow(row))}
                  </React.Fragment>
                )
              })
            ) : (
              pageRows.map((row) => renderRow(row))
            )}
          </tbody>
        </table>
      </div>

      <PaginatedTableFooter
        totalCount={grouped ? grouped.length : (useServerPagination ? (serverTotalCount ?? rows.length) : rows.length)}
        page={grouped ? safeGroupPage : safePage}
        perPage={grouped ? GROUPS_PER_PAGE : perPage}
        totalPages={grouped ? groupTotalPages : totalPages}
        onPageChange={grouped ? setLocalGroupPage : setPage}
        onPerPageChange={(n) => { if (!grouped) { setPerPage(n); if (!useServerPagination) setLocalPage(1) } }}
        label={grouped ? (groupLabel ?? "groups") : "findings"}
      />
    </div>
  )
}
