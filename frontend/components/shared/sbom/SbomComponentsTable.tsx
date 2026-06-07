"use client"

import { useState, useMemo } from "react"
import type { CycloneDxComponent } from "@/lib/client/sbom-api"
import { ComponentLicenseBadge } from "./ComponentLicenseBadge"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"

const PER_PAGE = 50

const TYPE_OPTIONS = ["library", "framework", "application", "container", "device", "firmware"]

function SkeletonRow() {
  return (
    <tr>
      {[60, 25, 20, 30, 45].map((w, i) => (
        <td key={i} className="px-4 py-3">
          <div
            className="h-3.5 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse"
            style={{ width: `${w}%` }}
          />
        </td>
      ))}
    </tr>
  )
}

export function SbomComponentsTable({
  components,
  loading,
}: {
  components: CycloneDxComponent[]
  loading: boolean
}) {
  const [search, setSearch] = useState("")
  const [typeFilter, setTypeFilter] = useState("all")
  const [page, setPage] = useState(1)

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return components.filter((c) => {
      const matchesType = typeFilter === "all" || c.type === typeFilter
      const matchesSearch =
        !q ||
        c.name.toLowerCase().includes(q) ||
        c.version.toLowerCase().includes(q) ||
        (c.purl?.toLowerCase().includes(q) ?? false)
      return matchesType && matchesSearch
    })
  }, [components, search, typeFilter])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PER_PAGE))
  const safeePage = Math.min(page, totalPages)
  const slice = filtered.slice((safeePage - 1) * PER_PAGE, safeePage * PER_PAGE)

  function handleSearch(val: string) {
    setSearch(val)
    setPage(1)
  }

  function handleType(val: string) {
    setTypeFilter(val)
    setPage(1)
  }

  return (
    <div className="flex flex-col overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-card)]">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-border)] px-4 py-3">
        <div className="relative flex-1 min-w-[160px]">
          <svg
            className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--color-text-tertiary)]"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.8}
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
          </svg>
          <input
            type="text"
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            placeholder="Search components…"
            className="h-8 w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] pl-8 pr-3 text-xs text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
          />
        </div>

        <select
          value={typeFilter}
          onChange={(e) => handleType(e.target.value)}
          className="h-8 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-2.5 text-xs text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
          aria-label="Filter by component type"
        >
          <option value="all">All types</option>
          {TYPE_OPTIONS.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>

        <span className="ml-auto text-[11px] tabular-nums text-[var(--color-text-tertiary)]">
          {loading ? "Loading…" : `${filtered.length.toLocaleString()} component${filtered.length !== 1 ? "s" : ""}`}
        </span>
      </div>

      {/* Table */}
      <div className="overflow-x-auto flex-1">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface-raised)]">
              <th className="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
                Name
              </th>
              <th className="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
                Version
              </th>
              <th className="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
                Type
              </th>
              <th className="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
                License
              </th>
              <th className="px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
                Hash
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)]">
            {loading ? (
              Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} />)
            ) : slice.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-12 text-center text-sm text-[var(--color-text-secondary)]">
                  {search || typeFilter !== "all"
                    ? "No components match the current filters."
                    : "No components found in this SBOM."}
                </td>
              </tr>
            ) : (
              slice.map((c, idx) => (
                <tr
                  key={`${c.purl ?? c.name}-${idx}`}
                  className="transition-colors hover:bg-[var(--color-surface-raised)]"
                >
                  <td className="px-4 py-2.5">
                    <div className="flex flex-col gap-0.5">
                      <span className="font-medium text-[var(--color-text-primary)] text-sm">
                        {c.name}
                      </span>
                      {c.purl && (
                        <code className="font-[family-name:var(--font-jetbrains-mono)] text-2xs text-[var(--color-text-tertiary)] truncate max-w-[28ch]">
                          {c.purl}
                        </code>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <code className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-secondary)]">
                      {c.version || "—"}
                    </code>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="rounded-full bg-[var(--color-surface-raised)] px-2 py-px text-2xs font-semibold text-[var(--color-text-secondary)]">
                      {c.type}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    {c.licenses && c.licenses.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {c.licenses.map((l) => (
                          <ComponentLicenseBadge key={l.license.id} spdxId={l.license.id} />
                        ))}
                      </div>
                    ) : (
                      <span className="text-[11px] text-[var(--color-text-tertiary)]">—</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    {c.hashes && c.hashes.length > 0 ? (
                      <code className="font-[family-name:var(--font-jetbrains-mono)] text-2xs text-[var(--color-text-tertiary)]" title={`${c.hashes[0].alg}: ${c.hashes[0].content}`}>
                        {c.hashes[0].alg.toLowerCase()}:{c.hashes[0].content.slice(0, 10)}…
                      </code>
                    ) : (
                      <span className="text-[11px] text-[var(--color-text-tertiary)]">—</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <PaginatedTableFooter
          totalCount={filtered.length}
          page={safeePage}
          perPage={PER_PAGE}
          totalPages={totalPages}
          onPageChange={setPage}
          onPerPageChange={() => {}}
          label="components"
        />
      )}
    </div>
  )
}
