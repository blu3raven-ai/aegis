"use client"

import { useState, useMemo } from "react"
import { componentVulnsFor, type CycloneDxComponent, type ComponentVulnsLookup, type DependencyOrigin } from "@/lib/client/sbom-api"
import { CATEGORY_META, CATEGORY_ORDER } from "@/lib/sbom/license-category"
import { ComponentLicenseBadge } from "./ComponentLicenseBadge"
import { DependencyOriginBadge } from "./DependencyOriginBadge"
import { ComponentVulnBadge } from "./ComponentVulnBadge"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"
import { Card } from "@/components/ui/Card"
import { SearchInput } from "@/components/shared/SearchInput"
import { Select } from "@/components/ui/Select"
import { Skeleton } from "@/components/ui/Skeleton"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"

const PER_PAGE = 50

const TYPE_OPTIONS = ["library", "framework", "application", "container", "device", "firmware"]

function SkeletonRow() {
  return (
    <Tr>
      {[60, 25, 22, 24, 30].map((w, i) => (
        <Td key={i}>
          <Skeleton
            className="h-3.5"
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
  vulns,
  vulnsLoading = false,
  directness,
}: {
  components: CycloneDxComponent[]
  loading: boolean
  /** Open-finding counts keyed by exact component name; absent until loaded. */
  vulns?: ComponentVulnsLookup
  vulnsLoading?: boolean
  /** Direct/transitive/unknown per component bom-ref (from deriveDirectness). */
  directness?: Map<string, DependencyOrigin>
}) {
  const [search, setSearch] = useState("")
  const [typeFilter, setTypeFilter] = useState("all")
  const [licenseFilter, setLicenseFilter] = useState("all")
  const [originFilter, setOriginFilter] = useState("all")
  const [page, setPage] = useState(1)

  const originOf = (c: CycloneDxComponent): DependencyOrigin =>
    (c.bomRef && directness?.get(c.bomRef)) || "unknown"

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return components.filter((c) => {
      const matchesType = typeFilter === "all" || c.type === typeFilter
      const matchesLicense = licenseFilter === "all" || c.licenseCategory === licenseFilter
      const matchesOrigin = originFilter === "all" || originOf(c) === originFilter
      const catLabel = c.licenseCategory ? CATEGORY_META[c.licenseCategory].label.toLowerCase() : ""
      const matchesSearch =
        !q ||
        c.name.toLowerCase().includes(q) ||
        c.version.toLowerCase().includes(q) ||
        (c.purl?.toLowerCase().includes(q) ?? false) ||
        (c.licenses?.some((l) => l.toLowerCase().includes(q)) ?? false) ||
        catLabel.includes(q)
      return matchesType && matchesLicense && matchesOrigin && matchesSearch
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [components, search, typeFilter, licenseFilter, originFilter, directness])

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

  function handleLicense(val: string) {
    setLicenseFilter(val)
    setPage(1)
  }

  function handleOrigin(val: string) {
    setOriginFilter(val)
    setPage(1)
  }

  return (
    <Card padding="none" elevation="sm" className="flex flex-col overflow-hidden rounded-xl">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-border)] px-4 py-3">
        <SearchInput
          size="sm"
          value={search}
          onChange={handleSearch}
          placeholder="Search components…"
          ariaLabel="Search components"
          className="flex-1 min-w-[160px]"
        />

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
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </option>
          ))}
        </Select>

        <Select
          size="sm"
          value={licenseFilter}
          onChange={(e) => handleLicense(e.target.value)}
          className="w-auto"
          aria-label="Filter by license risk"
        >
          <option value="all">All licenses</option>
          {CATEGORY_ORDER.map((cat) => (
            <option key={cat} value={cat}>
              {CATEGORY_META[cat].label}
            </option>
          ))}
        </Select>

        <Select
          size="sm"
          value={originFilter}
          onChange={(e) => handleOrigin(e.target.value)}
          className="w-auto"
          aria-label="Filter by dependency origin"
        >
          <option value="all">All origins</option>
          <option value="direct">Direct</option>
          <option value="transitive">Transitive</option>
          <option value="unknown">Unknown</option>
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
              <Th className="py-2.5">Vulnerabilities</Th>
              <Th className="py-2.5">Origin</Th>
              <Th className="py-2.5">License</Th>
            </Tr>
          </Thead>
          <Tbody>
            {loading ? (
              Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} />)
            ) : slice.length === 0 ? (
              <Tr>
                <Td colSpan={5} className="py-12 text-center text-sm text-[var(--color-text-secondary)]">
                  {search || typeFilter !== "all" || licenseFilter !== "all" || originFilter !== "all"
                    ? "No components match the current filters."
                    : "No components found in this SBOM."}
                </Td>
              </Tr>
            ) : (
              slice.map((c, idx) => (
                <Tr key={`${c.purl ?? c.name}-${idx}`} interactive>
                  <Td className="py-2.5">
                    <div className="flex min-w-0 flex-col gap-0.5">
                      <span className="truncate font-medium text-[var(--color-text-primary)] text-sm" title={c.name}>
                        {c.name}
                      </span>
                      {c.purl && (
                        <code className="font-[family-name:var(--font-jetbrains-mono)] text-2xs text-[var(--color-text-tertiary)] truncate max-w-[28ch]" title={c.purl}>
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
                    {vulnsLoading ? (
                      <Skeleton className="h-4 w-14" />
                    ) : (
                      <ComponentVulnBadge vulns={componentVulnsFor(vulns, c.name, c.version)} packageName={c.name} />
                    )}
                  </Td>
                  <Td className="py-2.5">
                    <DependencyOriginBadge origin={originOf(c)} />
                  </Td>
                  <Td className="py-2.5">
                    {c.licenses && c.licenses.length > 0 ? (
                      <ComponentLicenseBadge spdxId={c.licenses.join(" / ")} category={c.licenseCategory} />
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
    </Card>
  )
}
