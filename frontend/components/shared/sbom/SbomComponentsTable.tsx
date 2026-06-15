"use client"

import { useState, useMemo } from "react"
import type { CycloneDxComponent } from "@/lib/client/sbom-api"
import { ComponentLicenseBadge } from "./ComponentLicenseBadge"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"

const PER_PAGE = 50

const TYPE_OPTIONS = ["library", "framework", "application", "container", "device", "firmware"]

function SkeletonRow() {
  return (
    <Tr>
      {[60, 25, 20, 30, 45].map((w, i) => (
        <Td key={i}>
          <div
            className="h-3.5 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse"
            style={{ width: `${w}%` }}
          />
        </Td>
      ))}
    </Tr>
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
        <div className="flex-1 min-w-[160px]">
          <Input
            size="sm"
            type="text"
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
            placeholder="Search components…"
            leadingIcon={(
              <svg
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
            )}
          />
        </div>

        <Select
          size="sm"
          value={typeFilter}
          onChange={(e) => handleType(e.target.value)}
          className="w-auto"
          aria-label="Filter by component type"
        >
          <option value="all">All types</option>
          {TYPE_OPTIONS.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </Select>

        <span className="ml-auto text-[11px] tabular-nums text-[var(--color-text-tertiary)]">
          {loading ? "Loading…" : `${filtered.length.toLocaleString()} component${filtered.length !== 1 ? "s" : ""}`}
        </span>
      </div>

      {/* Table */}
      <div className="overflow-x-auto flex-1">
        <Table>
          <Thead>
            <Tr>
              <Th className="py-2.5">Name</Th>
              <Th className="py-2.5">Version</Th>
              <Th className="py-2.5">Type</Th>
              <Th className="py-2.5">License</Th>
              <Th className="py-2.5">Hash</Th>
            </Tr>
          </Thead>
          <Tbody>
            {loading ? (
              Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} />)
            ) : slice.length === 0 ? (
              <Tr>
                <Td colSpan={5} className="py-12 text-center text-sm text-[var(--color-text-secondary)]">
                  {search || typeFilter !== "all"
                    ? "No components match the current filters."
                    : "No components found in this SBOM."}
                </Td>
              </Tr>
            ) : (
              slice.map((c, idx) => (
                <Tr key={`${c.purl ?? c.name}-${idx}`} interactive>
                  <Td className="py-2.5">
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
                  </Td>
                  <Td className="py-2.5">
                    <code className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-secondary)]">
                      {c.version || "—"}
                    </code>
                  </Td>
                  <Td className="py-2.5">
                    <span className="rounded-full bg-[var(--color-surface-raised)] px-2 py-px text-2xs font-semibold text-[var(--color-text-secondary)]">
                      {c.type}
                    </span>
                  </Td>
                  <Td className="py-2.5">
                    {c.licenses && c.licenses.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {c.licenses.map((l) => (
                          <ComponentLicenseBadge key={l.license.id} spdxId={l.license.id} />
                        ))}
                      </div>
                    ) : (
                      <span className="text-[11px] text-[var(--color-text-tertiary)]">—</span>
                    )}
                  </Td>
                  <Td className="py-2.5">
                    {c.hashes && c.hashes.length > 0 ? (
                      <code className="font-[family-name:var(--font-jetbrains-mono)] text-2xs text-[var(--color-text-tertiary)]" title={`${c.hashes[0].alg}: ${c.hashes[0].content}`}>
                        {c.hashes[0].alg.toLowerCase()}:{c.hashes[0].content.slice(0, 10)}…
                      </code>
                    ) : (
                      <span className="text-[11px] text-[var(--color-text-tertiary)]">—</span>
                    )}
                  </Td>
                </Tr>
              ))
            )}
          </Tbody>
        </Table>
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
