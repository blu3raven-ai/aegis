"use client"

import React, { useEffect, useMemo, useRef, useState } from "react"
import type { DependenciesFinding } from "@/lib/shared/dependencies/types"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"
import { FindingsEmptyState } from "@/components/shared/FindingsEmptyState"
import { alertAgeDays, alertPatchVersion, cvssChipClass, formatCvssScore } from "@/lib/shared/dependencies/utils"
import type { AggregatedDependenciesFinding } from "@/app/(app)/dependencies/_components/findings-row"

type SortKey = "severity" | "cvss" | "age" | "repository" | "package"
type SortDir = "asc" | "desc"

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }

import { SEV_BADGE, STATE_BADGE } from "@/lib/shared/ui/badge-styles"

// PER_PAGE_OPTIONS moved to shared PaginatedTableFooter

function VersionCell({ alert }: { alert: DependenciesFinding }) {
  const current = alert.current_version ?? null
  const patch = alertPatchVersion(alert)

  if (current && patch) {
    return (
      <span className="flex items-center gap-1 whitespace-nowrap font-[family-name:var(--font-jetbrains-mono)] text-xs">
        <span className="text-[var(--color-text-primary)]">{current}</span>
        <span className="text-[var(--color-text-secondary)]">→</span>
        <span className="text-emerald-400">{patch}</span>
      </span>
    )
  }
  if (!current && patch) {
    return (
      <span className="flex items-center gap-1 whitespace-nowrap font-[family-name:var(--font-jetbrains-mono)] text-xs">
        <span className="text-[var(--color-text-secondary)]">Unknown</span>
        <span className="text-[var(--color-text-secondary)]">→</span>
        <span className="text-emerald-400">{patch}</span>
      </span>
    )
  }
  if (current && !patch) {
    return (
      <span className="flex items-center gap-1 whitespace-nowrap font-[family-name:var(--font-jetbrains-mono)] text-xs">
        <span className="text-[var(--color-text-primary)]">{current}</span>
        <span className="text-[var(--color-text-secondary)]">→</span>
        <span className="text-[var(--color-text-secondary)]">No patch</span>
      </span>
    )
  }
  // Neither current nor patch — fall back to vulnerable range
  const range = alert.security_vulnerability.vulnerable_version_range
  return (
    <span className="whitespace-nowrap font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]">
      {range || "—"}
    </span>
  )
}

export function FindingsTable({
  findings,
  selectedFindingKey,
  onSelectFinding,
  checkedKeys,
  onCheckedKeysChange,
  groupBy,
  renderGroupLabel,
  hideColumns,
  serverPage,
  serverPerPage,
  serverTotalCount,
  serverTotalPages,
  onServerPageChange,
  onServerPerPageChange,
}: {
  findings: AggregatedDependenciesFinding[]
  selectedFindingKey: string | null
  onSelectFinding: (finding: DependenciesFinding) => void
  checkedKeys?: Set<string>
  onCheckedKeysChange?: (keys: Set<string>) => void
  /** Group rows by this key. When set, collapsible group headers are shown. */
  groupBy?: (item: AggregatedDependenciesFinding) => string
  /** Custom label renderer for group headers */
  renderGroupLabel?: (key: string) => React.ReactNode
  /** Columns to hide (e.g. hide "repository" in repo view since it's the group header) */
  hideColumns?: Set<string>
  /** Server-side pagination — when provided, disables client-side slicing */
  serverPage?: number
  serverPerPage?: number
  serverTotalCount?: number
  serverTotalPages?: number
  onServerPageChange?: (page: number) => void
  onServerPerPageChange?: (perPage: number) => void
}) {
  const [sortKey, setSortKey] = useState<SortKey>("severity")
  const [sortDir, setSortDir] = useState<SortDir>("asc")
  const [localPage, setLocalPage]       = useState(1)
  const [localPerPage, setLocalPerPage] = useState(25)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const useServer = serverPage != null && onServerPageChange != null
  const page = useServer ? serverPage! : localPage
  const perPage = useServer ? (serverPerPage ?? 50) : localPerPage
  const setPage = useServer ? onServerPageChange! : setLocalPage
  const setPerPage = useServer ? (onServerPerPageChange ?? (() => {})) : setLocalPerPage

  const nowMs = useRef(Date.now())

  // Reset local page when findings change (e.g. filter change) — only in client-side mode
  const prevFindingsRef = useRef(findings)
  useEffect(() => {
    if (useServer) return
    if (prevFindingsRef.current !== findings) {
      prevFindingsRef.current = findings
      setLocalPage(1)
    }
  }, [findings, useServer])

  const sorted = useMemo(() => {
    nowMs.current = Date.now()
    return [...findings].sort((a, b) => {
      const ra = a.representative
      const rb = b.representative
      let cmp = 0
      if (sortKey === "severity") {
        cmp = (SEV_ORDER[ra.security_advisory.severity] ?? 9) - (SEV_ORDER[rb.security_advisory.severity] ?? 9)
      } else if (sortKey === "cvss") {
        cmp = (rb.security_advisory.cvss?.score ?? 0) - (ra.security_advisory.cvss?.score ?? 0)
      } else if (sortKey === "age") {
        cmp = alertAgeDays(ra, nowMs.current) - alertAgeDays(rb, nowMs.current)
      } else if (sortKey === "repository") {
        cmp = ra.repository.name.localeCompare(rb.repository.name)
      } else if (sortKey === "package") {
        cmp = ra.dependency.package.name.localeCompare(rb.dependency.package.name)
      }
      return sortDir === "asc" ? cmp : -cmp
    })
  }, [findings, sortKey, sortDir])

  const totalPages = useServer
    ? Math.max(1, serverTotalPages ?? 1)
    : Math.max(1, Math.ceil(sorted.length / perPage))
  const safePage   = Math.min(Math.max(page, 1), totalPages)
  // In server pagination mode, all rows are the current page (server already sliced)
  const pageFindings = useServer ? sorted : sorted.slice((safePage - 1) * perPage, safePage * perPage)

  function handleSort(key: SortKey) {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"))
    else { setSortKey(key); setSortDir("asc") }
    setPage(1)
  }

  function SortIndicator({ col }: { col: SortKey }) {
    if (sortKey !== col) return <span className="ml-1 text-[var(--color-text-secondary)]">↕</span>
    return <span className="ml-1 text-[var(--color-accent)]">{sortDir === "asc" ? "↑" : "↓"}</span>
  }

  const thCls     = "px-2.5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]"
  const thSortCls = `${thCls} cursor-pointer whitespace-nowrap hover:text-[var(--color-text-primary)]`

  const colCount = 6 // severity + cvss + state + version + manifests + age (always visible)
    + (onCheckedKeysChange ? 1 : 0)
    + (hideColumns?.has("package") ? 0 : 1)
    + (hideColumns?.has("organization") ? 0 : 1)
    + (hideColumns?.has("repository") ? 0 : 1)

  function toggleGroup(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  // Build grouped structure when groupBy is set
  const groups = useMemo(() => {
    if (!groupBy) return null
    const map = new Map<string, AggregatedDependenciesFinding[]>()
    for (const item of sorted) {
      const key = groupBy(item)
      const arr = map.get(key)
      if (arr) arr.push(item)
      else map.set(key, [item])
    }
    return [...map.entries()].map(([key, items]) => ({ key, items }))
  }, [groupBy, sorted])

  function renderRow(item: AggregatedDependenciesFinding) {
    const alert = item.representative
    const key = item.advisoryKey
    const age = Math.max(...item.findings.map((f) => Math.floor(alertAgeDays(f, nowMs.current))))
    const sev = alert.security_advisory.severity
    const cvss = alert.security_advisory.cvss.score
    const manifestCount = item.findings.length
    const isSelected = key === selectedFindingKey
    return (
      <tr
        key={key}
        onClick={() => onSelectFinding(alert)}
        className={`cursor-pointer border-b border-[var(--color-border)] transition-colors hover:bg-[var(--color-surface-raised)] ${
          isSelected ? "border-l-2 border-l-[var(--color-accent)] bg-[var(--color-accent)]/5" : ""
        }`}
      >
        {onCheckedKeysChange && (
          <td className="w-8 px-2 py-2.5" onClick={(e) => e.stopPropagation()}>
            <input
              type="checkbox"
              className="accent-[var(--color-accent)]"
              checked={checkedKeys?.has(key) ?? false}
              onChange={(e) => {
                const next = new Set(checkedKeys)
                if (e.target.checked) next.add(key)
                else next.delete(key)
                onCheckedKeysChange(next)
              }}
            />
          </td>
        )}
        <td className="px-2.5 py-2.5 whitespace-nowrap">
          <span className={`rounded-full px-1.5 py-0.5 text-[11px] font-semibold ${SEV_BADGE[sev] ?? ""}`}>{sev}</span>
        </td>
        <td className="px-2.5 py-2.5 whitespace-nowrap">
          <span className={`rounded-full px-1.5 py-0.5 text-[11px] font-semibold tabular-nums ${cvssChipClass(cvss)}`}>{formatCvssScore(cvss)}</span>
        </td>
        <td className="px-2.5 py-2.5 whitespace-nowrap">
          <span className={`rounded-full px-1.5 py-0.5 text-[11px] font-semibold ${STATE_BADGE[alert.state]?.cls ?? ""}`}>{STATE_BADGE[alert.state]?.label ?? alert.state}</span>
        </td>
        {!hideColumns?.has("package") && (
          <td className="px-2.5 py-2.5 max-w-[140px]">
            <span className="block truncate font-medium text-[var(--color-text-primary)] text-xs">{alert.dependency.package.name}</span>
            <span className="block text-[11px] text-[var(--color-text-secondary)]">{alert.dependency.package.ecosystem}</span>
          </td>
        )}
        <td className="px-2.5 py-2.5"><VersionCell alert={alert} /></td>
        {!hideColumns?.has("organization") && (
          <td className="px-2.5 py-2.5 whitespace-nowrap text-xs text-[var(--color-text-secondary)]">
            {alert.repository.full_name.includes("/") ? alert.repository.full_name.split("/")[0] : "—"}
          </td>
        )}
        {!hideColumns?.has("repository") && (
          <td className="px-2.5 py-2.5 whitespace-nowrap text-xs font-medium text-[var(--color-text-primary)]">{alert.repository.name}</td>
        )}
        <td className="px-2.5 py-2.5 max-w-[180px]">
          <span className="block truncate font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-secondary)]">{alert.dependency.manifest_path}</span>
          {manifestCount > 1 && (
            <span className="mt-0.5 inline-block rounded-md bg-[var(--color-surface-raised)] px-1 py-0.5 text-[10px] font-semibold text-[var(--color-text-secondary)]">+{manifestCount - 1}</span>
          )}
        </td>
        <td className="px-2.5 py-2.5 tabular-nums text-xs text-[var(--color-text-secondary)] whitespace-nowrap">{alert.created_at ? `${age}d` : "–"}</td>
      </tr>
    )
  }

  const isEmpty = groups ? groups.length === 0 : pageFindings.length === 0

  if (isEmpty) {
    return <FindingsEmptyState />
  }

  return (
    <div className="overflow-hidden">
      <div>
        <table className="w-full text-left text-sm">
          <thead className="border-b border-[var(--color-border)] bg-[var(--color-surface-raised)]">
            <tr>
              {onCheckedKeysChange && (
                <th className="w-8 px-2 py-2.5">
                  <input
                    type="checkbox"
                    className="accent-[var(--color-accent)]"
                    checked={pageFindings.length > 0 && pageFindings.every((f) => checkedKeys?.has(f.advisoryKey))}
                    onChange={(e) => {
                      const next = new Set(checkedKeys)
                      for (const f of pageFindings) {
                        if (e.target.checked) next.add(f.advisoryKey)
                        else next.delete(f.advisoryKey)
                      }
                      onCheckedKeysChange(next)
                    }}
                  />
                </th>
              )}
              <th className={thSortCls} onClick={() => handleSort("severity")}>
                Severity <SortIndicator col="severity" />
              </th>
              <th className={thSortCls} onClick={() => handleSort("cvss")}>
                CVSS <SortIndicator col="cvss" />
              </th>
              <th className={thCls}>State</th>
              {!hideColumns?.has("package") && (
                <th className={thSortCls} onClick={() => handleSort("package")}>
                  Package <SortIndicator col="package" />
                </th>
              )}
              <th className={thCls}>Version</th>
              {!hideColumns?.has("organization") && <th className={thCls}>Org</th>}
              {!hideColumns?.has("repository") && (
                <th className={thSortCls} onClick={() => handleSort("repository")}>
                  Repo <SortIndicator col="repository" />
                </th>
              )}
              <th className={thCls}>Manifests</th>
              <th className={thSortCls} onClick={() => handleSort("age")}>
                <span className="inline-flex items-center gap-1">
                  Age
                  <svg className="h-3 w-3 text-[var(--color-text-tertiary)]" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
                    <title>Days since CVE was publicly disclosed</title>
                    <path fillRule="evenodd" d="M15 8A7 7 0 111 8a7 7 0 0114 0zm-6 3.5a1 1 0 11-2 0 1 1 0 012 0zM8 5.5a1 1 0 00-.993.884L7 6.5v3a1 1 0 001.993.117L9 9.5v-3A1 1 0 008 5.5z" clipRule="evenodd" />
                  </svg>
                </span>
                <SortIndicator col="age" />
              </th>
            </tr>
          </thead>
          <tbody>
            {groups ? (
              groups.map(({ key: groupKey, items }) => {
                const isOpen = expanded.has(groupKey)
                const groupItemKeys = items.map((i) => i.advisoryKey)
                const allGroupChecked = onCheckedKeysChange && groupItemKeys.length > 0 && groupItemKeys.every((k) => checkedKeys?.has(k))
                return (
                  <React.Fragment key={groupKey}>
                    <tr
                      className="cursor-pointer border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] transition-colors hover:brightness-110"
                      onClick={() => toggleGroup(groupKey)}
                    >
                      {onCheckedKeysChange && (
                        <td className="w-8 px-2 py-2.5" onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            className="accent-[var(--color-accent)]"
                            checked={!!allGroupChecked}
                            onChange={() => {
                              const next = new Set(checkedKeys)
                              for (const k of groupItemKeys) {
                                if (allGroupChecked) next.delete(k)
                                else next.add(k)
                              }
                              onCheckedKeysChange!(next)
                            }}
                          />
                        </td>
                      )}
                      <td colSpan={colCount - (onCheckedKeysChange ? 1 : 0)} className="px-2.5 py-2.5">
                        <div className="flex items-center gap-2.5">
                          <svg
                            className={`h-4 w-4 shrink-0 text-[var(--color-text-secondary)] transition-transform duration-200 ${isOpen ? "rotate-90" : ""}`}
                            viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"
                          >
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                          <span className="font-semibold text-sm text-[var(--color-text-primary)]">
                            {renderGroupLabel ? renderGroupLabel(groupKey) : groupKey}
                          </span>
                          <span className="rounded-md bg-[var(--color-surface)] px-2 py-0.5 text-xs font-semibold tabular-nums text-[var(--color-text-secondary)]">
                            {items.length}
                          </span>
                        </div>
                      </td>
                    </tr>
                    {isOpen && items.map((item) => renderRow(item))}
                  </React.Fragment>
                )
              })
            ) : (
              pageFindings.map((item) => renderRow(item))
            )}
          </tbody>
        </table>
      </div>

      <PaginatedTableFooter
        totalCount={useServer ? (serverTotalCount ?? sorted.length) : sorted.length}
        page={safePage}
        perPage={perPage}
        totalPages={totalPages}
        onPageChange={setPage}
        onPerPageChange={(n) => { setPerPage(n); if (!useServer) setLocalPage(1) }}
      />
    </div>
  )
}
