"use client"

import React, { useEffect, useMemo, useRef, useState } from "react"
import type { CodeScanningFinding } from "@/lib/client/code-scanning-client"
import { FindingsEmptyState } from "@/components/shared/FindingsEmptyState"
import { CollapsibleGroupHeader } from "@/components/shared/CollapsibleGroupHeader"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"

const ROWS_PER_PAGE = 50
const GROUPS_PER_PAGE = 20

const SEV_ORDER: Record<CodeScanningFinding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

import { sevBadgeClass, stateBadgeClass, stateBadgeLabel } from "@/lib/shared/ui/badge-styles"

const severityBadgeClass = sevBadgeClass

function aiVerdictDot(verdict: string): string {
  const v = verdict.toLowerCase()
  if (v.includes("false positive") || v.includes("not exploitable") || v.includes("benign") || v.includes("unlikely"))
    return "bg-[var(--color-verdict-safe)]"
  if (v.includes("true positive") || v.includes("confirmed") || v.includes("exploitable") || v.includes("vulnerable"))
    return "bg-[var(--color-verdict-risk)]"
  if (v.includes("likely"))
    return "bg-[var(--color-verdict-uncertain)]"
  return "bg-[var(--color-verdict-neutral)]"
}

function stateLabel(state: CodeScanningFinding["state"]): string {
  switch (state) {
    case "open":         return "Open"
    case "dismissed":    return "Dismissed"
    case "fixed":        return "Fixed"
    case "awaiting_fix": return "Awaiting Fix"
  }
}

function ageDays(iso?: string): string {
  if (!iso) return "–"
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000)
  return `${days}d`
}

interface Props {
  rows: CodeScanningFinding[]
  selected: Set<string>
  activeFinding: CodeScanningFinding | null
  onToggleSelect: (key: string) => void
  onSetSelected: (keys: string[], shouldSelect: boolean) => void
  onSelectFinding: (finding: CodeScanningFinding) => void
  totalCount: number
  initialExpandedRepo?: string
  groupBy?: (item: CodeScanningFinding) => string
  renderGroupLabel?: (key: string) => React.ReactNode
  hideColumns?: Set<string>
  groupLabel?: string
}

export function CodeScanningRepoGroupedFindings({
  rows,
  selected,
  activeFinding,
  onToggleSelect,
  onSetSelected,
  onSelectFinding,
  totalCount,
  initialExpandedRepo,
  groupBy,
  renderGroupLabel,
  hideColumns,
  groupLabel,
}: Props) {
  const [expandedRepos, setExpandedRepos] = useState<Set<string>>(() =>
    initialExpandedRepo ? new Set([initialExpandedRepo]) : new Set()
  )
  const [localPage, setLocalPage] = useState(1)
  const [localGroupPage, setLocalGroupPage] = useState(1)

  // Reset row page when rows change
  const prevRowsRef = useRef(rows)
  useEffect(() => {
    if (prevRowsRef.current !== rows) {
      prevRowsRef.current = rows
      setLocalPage(1)
    }
  }, [rows])

  const grouped = useMemo(() => {
    if (!groupBy) return null
    const map = new Map<string, CodeScanningFinding[]>()
    for (const f of rows) {
      const key = groupBy(f)
      const existing = map.get(key) ?? []
      existing.push(f)
      map.set(key, existing)
    }
    return Array.from(map.entries())
      .map(([key, findings]) => {
        const sorted = [...findings].sort((a, b) => {
          const sevDiff = SEV_ORDER[a.severity] - SEV_ORDER[b.severity]
          if (sevDiff !== 0) return sevDiff
          return (a.first_seen_at ?? "").localeCompare(b.first_seen_at ?? "")
        })
        return [key, sorted] as [string, CodeScanningFinding[]]
      })
      .sort((a, b) => b[1].length - a[1].length)
  }, [rows, groupBy])

  // Reset group page when groups change
  const prevGroupsLengthRef = useRef<number | null>(null)
  useEffect(() => {
    const len = grouped ? grouped.length : null
    if (prevGroupsLengthRef.current !== len) {
      prevGroupsLengthRef.current = len
      setLocalGroupPage(1)
    }
  }, [grouped])

  // Pagination
  const rowTotalPages = Math.max(1, Math.ceil(rows.length / ROWS_PER_PAGE))
  const safePage = Math.min(Math.max(localPage, 1), rowTotalPages)
  const pageRows = rows.slice((safePage - 1) * ROWS_PER_PAGE, safePage * ROWS_PER_PAGE)

  const groupTotalPages = grouped ? Math.max(1, Math.ceil(grouped.length / GROUPS_PER_PAGE)) : 1
  const safeGroupPage = Math.min(Math.max(localGroupPage, 1), groupTotalPages)
  const pageGroups = grouped
    ? grouped.slice((safeGroupPage - 1) * GROUPS_PER_PAGE, safeGroupPage * GROUPS_PER_PAGE)
    : null

  function toggleRepo(repo: string) {
    setExpandedRepos((current) => {
      const next = new Set(current)
      if (next.has(repo)) next.delete(repo)
      else next.add(repo)
      return next
    })
  }

  const allRowKeys = useMemo(() => rows.map((f) => f.identity_key), [rows])
  const selectedVisibleCount = allRowKeys.filter((k) => selected.has(k)).length
  const allVisibleSelected = allRowKeys.length > 0 && selectedVisibleCount === allRowKeys.length

  if (rows.length === 0) {
    return <FindingsEmptyState />
  }

  function renderRow(finding: CodeScanningFinding) {
    const isActive = activeFinding?.identity_key === finding.identity_key
    return (
      <tr
        key={finding.identity_key}
        onClick={() => onSelectFinding(finding)}
        tabIndex={0}
        role="button"
        aria-label={`Open finding: ${finding.rule_name}`}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault()
            onSelectFinding(finding)
          }
        }}
        className={`cursor-pointer border-b border-[var(--color-border)] transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset ${
          isActive ? "bg-[var(--color-accent)]/5" : ""
        }`}
      >
        <td className="w-8 px-2 py-2.5" onClick={(e) => e.stopPropagation()}>
          <input
            type="checkbox"
            checked={selected.has(finding.identity_key)}
            onChange={() => onToggleSelect(finding.identity_key)}
            className="cursor-pointer accent-[var(--color-accent)]"
          />
        </td>
        <td className="px-2.5 py-2.5 whitespace-nowrap">
          <span className={`rounded-full px-1.5 py-0.5 text-[11px] font-semibold capitalize ${severityBadgeClass(finding.severity)}`}>{finding.severity}</span>
        </td>
        <td className="px-2.5 py-2.5 whitespace-nowrap">
          <span className={`rounded-full px-1.5 py-0.5 text-[11px] font-semibold ${stateBadgeClass(finding.state)}`}>{stateLabel(finding.state)}</span>
        </td>
        {!hideColumns?.has("rule") && (
          <td className="px-2.5 py-2.5 overflow-hidden">
            <span className="block truncate text-xs font-medium text-[var(--color-text-primary)]">{finding.rule_name}</span>
            <span className="block truncate text-[11px] text-[var(--color-text-secondary)]">{finding.rule_id.split(".").slice(-2).join(".")}</span>
          </td>
        )}
        {!hideColumns?.has("repository") && (
          <td className="px-2.5 py-2.5 whitespace-nowrap text-xs font-medium text-[var(--color-text-primary)]">{finding.repo_full_name}</td>
        )}
        <td className="px-2.5 py-2.5 whitespace-nowrap font-mono text-[11px] text-[var(--color-text-primary)]">
          {finding.file_path.split("/").pop()}:{finding.start_line}
        </td>
        <td className="px-2.5 py-2.5 whitespace-nowrap">
          {finding.ai_review && finding.ai_review.verdict !== "skipped" && (
            <span
              title={finding.ai_review.verdict}
              className={`inline-block h-2 w-2 rounded-full ${aiVerdictDot(finding.ai_review.verdict)}`}
            />
          )}
        </td>
        <td className="px-2.5 py-2.5 whitespace-nowrap tabular-nums text-xs text-[var(--color-text-secondary)]">{ageDays(finding.first_seen_at)}</td>
      </tr>
    )
  }

  const thCls = "px-2.5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]"
  const colCount = 6 + (hideColumns?.has("rule") ? 0 : 1) + (hideColumns?.has("repository") ? 0 : 1)

  return (
    <div className="overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 text-xs text-[var(--color-text-secondary)]">
        <span>
          {grouped
            ? `${grouped.length} ${groupLabel ?? "groups"}`
            : `${totalCount} finding${totalCount !== 1 ? "s" : ""}`}
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
              <button type="button" onClick={() => setExpandedRepos(new Set((grouped ?? []).map(([k]) => k)))} className="rounded px-2 py-1 hover:bg-[var(--color-surface-raised)]">
                Expand all
              </button>
              <button type="button" onClick={() => setExpandedRepos(new Set())} className="rounded px-2 py-1 hover:bg-[var(--color-surface-raised)]">
                Collapse all
              </button>
            </>
          )}
        </div>
      </div>

      <div className="overflow-x-auto">
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
              <th className={`${thCls} w-[80px]`}>Severity</th>
              <th className={`${thCls} w-[110px]`}>State</th>
              {!hideColumns?.has("rule") && <th className={thCls}>Rule</th>}
              {!hideColumns?.has("repository") && <th className={`${thCls} w-[160px]`}>Repo</th>}
              <th className={`${thCls} w-[160px]`}>File</th>
              <th className={`${thCls} w-[32px]`}>AI</th>
              <th className={`${thCls} w-[54px]`}>
                <span className="inline-flex items-center gap-1">
                  Age
                  <svg className="h-3 w-3 text-[var(--color-text-tertiary)]" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
                    <title>Days since first detected by scanner</title>
                    <path fillRule="evenodd" d="M15 8A7 7 0 111 8a7 7 0 0114 0zm-6 3.5a1 1 0 11-2 0 1 1 0 012 0zM8 5.5a1 1 0 00-.993.884L7 6.5v3a1 1 0 001.993.117L9 9.5v-3A1 1 0 008 5.5z" clipRule="evenodd" />
                  </svg>
                </span>
              </th>
            </tr>
          </thead>
          <tbody>
            {pageGroups ? (
              pageGroups.map(([groupKey, groupFindings]) => {
                const isExpanded = expandedRepos.has(groupKey)
                const groupRowKeys = groupFindings.map((f) => f.identity_key)
                const selectedGroupCount = groupRowKeys.filter((k) => selected.has(k)).length
                const allGroupSelected = groupRowKeys.length > 0 && selectedGroupCount === groupRowKeys.length
                return (
                  <React.Fragment key={groupKey}>
                    <CollapsibleGroupHeader
                      label={renderGroupLabel ? renderGroupLabel(groupKey) as string : groupKey}
                      count={groupFindings.length}
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
                    {isExpanded && groupFindings.map((f) => renderRow(f))}
                  </React.Fragment>
                )
              })
            ) : (
              pageRows.map((f) => renderRow(f))
            )}
          </tbody>
        </table>
      </div>

      <PaginatedTableFooter
        totalCount={grouped ? grouped.length : totalCount}
        page={grouped ? safeGroupPage : safePage}
        perPage={grouped ? GROUPS_PER_PAGE : ROWS_PER_PAGE}
        totalPages={grouped ? groupTotalPages : rowTotalPages}
        onPageChange={grouped ? setLocalGroupPage : setLocalPage}
        onPerPageChange={() => {}}
        label={grouped ? (groupLabel ?? "groups") : "findings"}
      />
    </div>
  )
}
