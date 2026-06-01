"use client"

import { useState, useEffect, useCallback } from "react"
import Link from "next/link"
import { FilterTag } from "@/components/shared/FilterTag"
import { PaginatedTableFooter } from "@/components/shared/PaginatedTableFooter"
import { ChainBadge } from "@/components/shared/chain/ChainBadge"
import { PageHeader } from "@/components/layout/PageHeader"
import { ChainsIcon } from "@/lib/shared/ui/page-icons"
import { listChains, type Chain } from "@/lib/client/chains-api"
import { useSSE } from "@/components/providers/SSEProvider"
import type { ArgusIntelPushEvent } from "@/lib/shared/sse-types"

// ── Constants ─────────────────────────────────────────────────────────────────

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

const SEV_COLOR: Record<string, string> = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
}

const STATUS_COLOR: Record<string, string> = {
  open: "var(--color-text-primary)",
  acknowledged: "var(--color-text-secondary)",
  resolved: "var(--color-status-ok)",
}

const PER_PAGE = 10

function formatDate(iso: string) {
  if (!iso) return "—"
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })
}

export default function ChainsListPage() {
  const [chains, setChains] = useState<Chain[]>([])
  const [sevFilter, setSevFilter] = useState<string>("all")
  const [typeFilter, setTypeFilter] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [hasLiveUpdate, setHasLiveUpdate] = useState(false)

  const loadChains = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await listChains(ORG_ID, {
        severity: sevFilter !== "all" ? sevFilter : undefined,
        chainType: typeFilter ?? undefined,
      })
      setChains(result.chains ?? [])
    } catch {
      setError("Failed to load attack chains")
      setChains([])
    } finally {
      setLoading(false)
    }
  }, [sevFilter, typeFilter])

  useEffect(() => { void loadChains() }, [loadChains])

  useSSE("argus.intel_push", (_data: ArgusIntelPushEvent) => {
    setHasLiveUpdate(true)
  })

  const filtered = chains.filter((c) => {
    if (sevFilter !== "all" && c.severity !== sevFilter) return false
    if (typeFilter && c.chain_type !== typeFilter) return false
    return true
  })

  const totalPages = Math.max(1, Math.ceil(filtered.length / PER_PAGE))
  const pageChains = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE)

  const chainTypes = Array.from(new Set(chains.map((c) => c.chain_type)))

  return (
    <div className="flex h-full flex-col overflow-hidden bg-[var(--color-bg)]">
      <PageHeader
        icon={<ChainsIcon />}
        title="Attack Chains"
        description="Correlated multi-signal attack chains. Click a chain to explore the graph."
        controls={
          <div className="flex items-center gap-2">
            {hasLiveUpdate && (
              <span className="inline-flex items-center gap-1 rounded-full bg-[var(--color-state-dismissed-subtle)] border border-[var(--color-state-dismissed-border)] px-2 py-0.5 text-[11px] text-[var(--color-state-dismissed)]">
                <span className="inline-block h-1.5 w-1.5 rounded-full animate-[scan-pulse_2s_ease-in-out_infinite] bg-[var(--color-state-dismissed)]" />
                Live
              </span>
            )}
            <span className="rounded-full bg-[var(--color-bg-section)] border border-[var(--color-border)] px-2.5 py-0.5 text-[11px] tabular-nums text-[var(--color-text-secondary)]">
              {chains.length}
            </span>
          </div>
        }
      />

      {/* Filter row */}
      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-2.5">
        {/* Severity filter */}
        <div
          className="flex items-center rounded-lg border border-[var(--color-border)] overflow-hidden"
          role="radiogroup"
          aria-label="Filter by severity"
        >
          {["all", "critical", "high", "medium", "low"].map((sev) => (
            <button
              key={sev}
              type="button"
              role="radio"
              aria-checked={sevFilter === sev}
              onClick={() => { setSevFilter(sev); setPage(1) }}
              className={`px-3 py-1.5 text-xs font-semibold transition-colors border-r last:border-r-0 border-[var(--color-border)] capitalize ${
                sevFilter === sev
                  ? "bg-[var(--color-accent)] text-[var(--color-accent-on)]"
                  : "bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              {sev === "all" ? "All" : sev}
            </button>
          ))}
        </div>

        {/* Chain type filter */}
        <select
          value={typeFilter ?? ""}
          onChange={(e) => { setTypeFilter(e.target.value || null); setPage(1) }}
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs text-[var(--color-text-secondary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]"
          aria-label="Filter by chain type"
        >
          <option value="">All types</option>
          {chainTypes.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>

        {/* Active filter tags */}
        {sevFilter !== "all" && (
          <FilterTag label={`Severity: ${sevFilter}`} onClear={() => { setSevFilter("all"); setPage(1) }} />
        )}
        {typeFilter && (
          <FilterTag label={`Type: ${typeFilter}`} onClear={() => { setTypeFilter(null); setPage(1) }} />
        )}

        <div className="ml-auto">
          <Link
            href="/findings"
            className="text-xs text-[var(--color-accent)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
          >
            ← All findings
          </Link>
        </div>
      </div>

      {/* Chains table */}
      <div className="flex-1 overflow-auto">
        {error && (
          <div className="flex items-center justify-between border-b border-[var(--color-border-divider)] px-5 py-3 text-[12px] text-[var(--color-severity-high)]">
            <span>{error}</span>
            <button
              type="button"
              onClick={() => void loadChains()}
              className="rounded-md border border-[var(--color-border)] px-2 py-1 text-[11px] font-semibold text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-border-strong)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] transition-colors"
            >
              Retry
            </button>
          </div>
        )}
        {!error && loading ? (
          <div className="space-y-px" aria-busy="true" aria-label="Loading chains">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-4 px-4 py-3 border-b border-[var(--color-border-divider)]">
                <div className="h-5 w-32 motion-safe:animate-pulse rounded bg-[var(--color-surface-raised)]" />
                <div className="h-4 w-14 motion-safe:animate-pulse rounded bg-[var(--color-surface-raised)]" />
                <div className="h-4 w-20 motion-safe:animate-pulse rounded bg-[var(--color-surface-raised)]" />
                <div className="ml-auto h-4 w-28 motion-safe:animate-pulse rounded bg-[var(--color-surface-raised)]" />
              </div>
            ))}
          </div>
        ) : pageChains.length === 0 ? (
          <div className="flex min-h-[260px] flex-col items-center justify-center gap-2 px-8 text-center">
            <p className="text-[13px] font-medium text-[var(--color-text-primary)]">No chains match the current filters</p>
            <p className="text-[12px] text-[var(--color-text-secondary)] max-w-[36ch]">
              {sevFilter !== "all" || typeFilter
                ? "Try clearing the active filters to see all chains."
                : "Chains appear when Aegis correlates findings from multiple scanners into a single exploit path."}
            </p>
            {(sevFilter !== "all" || typeFilter) && (
              <button
                type="button"
                onClick={() => { setSevFilter("all"); setTypeFilter(null) }}
                className="mt-2 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-border-strong)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
              >
                Clear filters
              </button>
            )}
          </div>
        ) : (
          <table className="w-full border-collapse text-[13px]">
            <thead className="sticky top-0 z-10 bg-[var(--color-surface)]">
              <tr className="border-b border-[var(--color-border)]">
                <th className="px-4 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Chain</th>
                <th className="px-3 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Severity</th>
                <th className="px-3 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Status</th>
                <th className="px-3 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)] hidden md:table-cell">Last updated</th>
                <th className="px-3 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)] hidden lg:table-cell">Created</th>
                <th className="w-24 px-3 py-2.5 text-right text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]" />
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--color-border-divider)]">
              {pageChains.map((chain) => (
                <tr
                  key={chain.id}
                  className="hover:bg-[var(--color-bg-hover)] transition-colors"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <ChainBadge chainType={chain.chain_type} size="md" />
                      <span className="font-[family-name:var(--font-jetbrains-mono)] text-[10.5px] text-[var(--color-text-tertiary)]">
                        {chain.id.slice(0, 12)}…
                      </span>
                    </div>
                  </td>

                  <td className="px-3 py-3">
                    <span
                      className="text-[11px] font-semibold uppercase"
                      style={{ color: SEV_COLOR[chain.severity] ?? SEV_COLOR.low }}
                    >
                      {chain.severity}
                    </span>
                  </td>

                  <td className="px-3 py-3">
                    <span
                      className="text-[11px] font-medium capitalize"
                      style={{ color: STATUS_COLOR[chain.status] ?? "var(--color-text-secondary)" }}
                    >
                      {chain.status}
                    </span>
                  </td>

                  <td className="px-3 py-3 hidden md:table-cell">
                    <span className="text-[11px] text-[var(--color-text-tertiary)]">
                      {formatDate(chain.last_updated_at)}
                    </span>
                  </td>

                  <td className="px-3 py-3 hidden lg:table-cell">
                    <span className="text-[11px] text-[var(--color-text-tertiary)]">
                      {formatDate(chain.created_at)}
                    </span>
                  </td>

                  <td className="px-3 py-3 text-right">
                    <Link
                      href={`/chains/${chain.id}`}
                      className="text-xs font-medium text-[var(--color-accent)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] rounded"
                    >
                      Graph →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <PaginatedTableFooter
          totalCount={filtered.length}
          page={page}
          perPage={PER_PAGE}
          totalPages={totalPages}
          onPageChange={setPage}
          onPerPageChange={() => {}}
          label="chains"
        />
      </div>
    </div>
  )
}
