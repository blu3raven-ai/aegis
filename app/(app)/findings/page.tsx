"use client"

import { useState, useCallback, useEffect, useMemo, useRef } from "react"
import Link from "next/link"
import { FindingsEmptyState } from "@/components/shared/FindingsEmptyState"
import { FilterTag } from "@/components/shared/FilterTag"
import { ViewModeToggle, type ViewMode } from "@/components/shared/ViewModeToggle"
import { FindingsDrawerShell } from "@/components/shared/FindingsDrawerShell"
import { DrawerHeader } from "@/components/shared/FindingDrawer/DrawerHeader"
import { DrawerSection } from "@/components/shared/FindingDrawer/DrawerSection"
import { RiskScoreCell } from "@/components/shared/chain/RiskScoreCell"
import { IntelLiveBanner } from "@/components/shared/chain/IntelLiveBanner"
import { useSSE } from "@/components/providers/SSEProvider"
import type { ArgusIntelPushEvent } from "@/lib/shared/sse-types"
import { ExportFindingsButton } from "@/components/shared/findings/ExportFindingsButton"
import { EpssScoreCell } from "@/components/shared/findings/EpssScoreCell"
import { PageHeader } from "@/components/layout/PageHeader"
import { FindingsIcon } from "@/lib/shared/ui/page-icons"
import { listFindings } from "@/lib/client/findings-api"
import {
  mapApiFinding,
  type FindingRow as Finding,
  type FindingScanner as Scanner,
  type FindingSeverity as Severity,
} from "@/lib/shared/findings/row-mapper"

// ── Constants ────────────────────────────────────────────────────────────────

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"
const PAGE_SIZE = 50

const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
}

const SCANNER_LABEL: Record<Scanner, string> = {
  deps: "SCA",
  sast: "SAST",
  containers: "CONT",
  secrets: "SEC",
  iac: "IaC",
}

const SCANNER_BG: Record<Scanner, string> = {
  deps: "rgba(15,188,255,0.18)",
  sast: "rgba(192,132,252,0.18)",
  containers: "rgba(52,211,153,0.18)",
  secrets: "rgba(251,146,60,0.18)",
  iac: "rgba(96,165,250,0.18)",
}

const SCANNER_FG: Record<Scanner, string> = {
  deps: "#5fcdff",
  sast: "#d4b0fc",
  containers: "#6ee0b4",
  secrets: "#ffba7c",
  iac: "#93c2fa",
}

const SEVERITY_FILTERS: { label: string; value: Severity | "all" }[] = [
  { label: "All", value: "all" },
  { label: "Critical", value: "critical" },
  { label: "High", value: "high" },
  { label: "Medium", value: "medium" },
  { label: "Low", value: "low" },
]

const VIEW_MODES: ViewMode[] = [
  {
    id: "all",
    label: "All",
    icon: (
      <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
        <line x1="8" y1="6" x2="21" y2="6" /><line x1="8" y1="12" x2="21" y2="12" /><line x1="8" y1="18" x2="21" y2="18" />
        <line x1="3" y1="6" x2="3.01" y2="6" /><line x1="3" y1="12" x2="3.01" y2="12" /><line x1="3" y1="18" x2="3.01" y2="18" />
      </svg>
    ),
  },
  {
    id: "chained",
    label: "Chained",
    icon: (
      <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
      </svg>
    ),
  },
]

// ── Component ─────────────────────────────────────────────────────────────────

type SortDirection = "asc" | "desc" | null

export default function FindingsInboxPage() {
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all")
  const [viewMode, setViewMode] = useState("all")
  const [findings, setFindings] = useState<Finding[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [totalCount, setTotalCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [intelMessage, setIntelMessage] = useState<string | null>(null)
  const [epssSort, setEpssSort] = useState<SortDirection>(null)
  const dismissedIntelRef = useRef(false)

  useSSE("argus.intel_push", (data: ArgusIntelPushEvent) => {
    if (!dismissedIntelRef.current) {
      setIntelMessage(data.message ?? "New Argus intel available — chain risk scores updated.")
    }
  })

  const handleIntelDismiss = useCallback(() => {
    dismissedIntelRef.current = true
    setIntelMessage(null)
  }, [])

  const load = useCallback(async (severity: Severity | "all") => {
    setLoading(true)
    setError(null)
    try {
      const resp = await listFindings({
        orgId: ORG_ID,
        limit: PAGE_SIZE,
        ...(severity !== "all" ? { severity: [severity] } : {}),
      })
      setFindings(resp.findings.map(mapApiFinding))
      setNextCursor(resp.next_cursor)
      setTotalCount(resp.total_count)
    } catch {
      setError("Failed to load findings. Please try again.")
      setFindings([])
      setNextCursor(null)
      setTotalCount(0)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load(sevFilter)
  }, [sevFilter, load])

  const handleLoadMore = useCallback(async () => {
    if (!nextCursor || loadingMore) return
    setLoadingMore(true)
    try {
      const resp = await listFindings({
        orgId: ORG_ID,
        limit: PAGE_SIZE,
        cursor: nextCursor,
        ...(sevFilter !== "all" ? { severity: [sevFilter] } : {}),
      })
      setFindings((prev) => [...prev, ...resp.findings.map(mapApiFinding)])
      setNextCursor(resp.next_cursor)
    } catch {
      setError("Failed to load more findings.")
    } finally {
      setLoadingMore(false)
    }
  }, [nextCursor, loadingMore, sevFilter])

  const handleRetry = useCallback(() => {
    void load(sevFilter)
  }, [load, sevFilter])

  // View mode "chained" stays a client-side filter — chain correlation data
  // is not in the aggregated endpoint shape, so all rows render unchained
  // until the chains projection is layered on top.
  const filtered = useMemo(
    () => (viewMode === "chained" ? [] : findings),
    [findings, viewMode],
  )

  // EPSS sort runs client-side over the loaded page. Server-side EPSS sort
  // is a follow-up once the backend exposes it as a sort key.
  const sorted = useMemo(() => {
    if (!epssSort) return filtered
    return [...filtered].sort((a, b) => {
      const av = a.epssPercentile ?? Number.NEGATIVE_INFINITY
      const bv = b.epssPercentile ?? Number.NEGATIVE_INFINITY
      if (av === bv) return 0
      const cmp = av < bv ? -1 : 1
      return epssSort === "asc" ? cmp : -cmp
    })
  }, [filtered, epssSort])

  function toggleEpssSort() {
    setEpssSort((cur) => (cur === "desc" ? "asc" : cur === "asc" ? null : "desc"))
  }

  const showEmpty = !loading && !error && sorted.length === 0
  const showTable = !loading && !error && sorted.length > 0

  return (
    <div className="flex h-full flex-col overflow-hidden bg-[var(--color-bg)]">
      <IntelLiveBanner message={intelMessage} onDismiss={handleIntelDismiss} />

      <PageHeader
        icon={<FindingsIcon />}
        title="Findings"
        description="Unified cross-scanner findings with chain correlation and Argus risk scoring."
        controls={
          <span className="rounded-full bg-[var(--color-bg-section)] border border-[var(--color-border)] px-2.5 py-0.5 text-[11px] tabular-nums text-[var(--color-text-secondary)]">
            {totalCount}
          </span>
        }
      />

      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-2.5">
        <div className="flex items-center rounded-lg border border-[var(--color-border)] overflow-hidden" role="radiogroup" aria-label="Filter by severity">
          {SEVERITY_FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              role="radio"
              aria-checked={sevFilter === f.value}
              onClick={() => setSevFilter(f.value)}
              className={`px-3 py-1.5 text-xs font-semibold transition-colors border-r last:border-r-0 border-[var(--color-border)] ${
                sevFilter === f.value
                  ? "bg-[var(--color-accent)] text-[var(--color-accent-on)]"
                  : "bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        <div className="w-px h-5 bg-[var(--color-border)] mx-1" />

        <ViewModeToggle
          modes={VIEW_MODES}
          active={viewMode}
          onChange={setViewMode}
          counts={{ all: totalCount, chained: 0 }}
        />

        {sevFilter !== "all" && (
          <FilterTag
            label={`Severity: ${sevFilter}`}
            onClear={() => setSevFilter("all")}
            color="accent"
          />
        )}
        {viewMode === "chained" && (
          <FilterTag
            label="Chained only"
            onClear={() => setViewMode("all")}
            color="accent"
          />
        )}

        <div className="ml-auto flex items-center gap-2">
          <ExportFindingsButton filters={sevFilter !== "all" ? { severity: sevFilter } : {}} />
          <Link
            href="/chains"
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border-medium)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-border-strong)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] transition-colors"
          >
            View Chains
            <svg className="h-3 w-3" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <path d="M3 8h10M9 4l4 4-4 4" />
            </svg>
          </Link>
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        {loading && (
          <div className="px-5 py-6 text-[12px] text-[var(--color-text-tertiary)]">
            Loading findings…
          </div>
        )}

        {error && (
          <div className="flex items-center justify-between border-b border-[var(--color-border-divider)] px-5 py-3 text-[12px] text-[var(--color-severity-high)]">
            <span>{error}</span>
            <button
              type="button"
              onClick={handleRetry}
              className="rounded-md border border-[var(--color-border)] px-2 py-1 text-[11px] font-semibold text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-border-strong)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] transition-colors"
            >
              Retry
            </button>
          </div>
        )}

        {showEmpty && (
          <FindingsEmptyState
            message={
              sevFilter !== "all" && viewMode === "chained"
                ? `No chained ${sevFilter} findings.`
                : sevFilter !== "all"
                ? `No ${sevFilter} findings.`
                : viewMode === "chained"
                ? "No chained findings. Aegis correlates multi-scanner findings into attack chains when a dependency, code path, and exposed endpoint align."
                : "No findings yet. Connect a source to start scanning."
            }
            onClearFilters={
              sevFilter !== "all" || viewMode !== "all"
                ? () => { setSevFilter("all"); setViewMode("all") }
                : undefined
            }
          />
        )}

        {showTable && (
          <>
            <table className="w-full border-collapse text-[13px]">
              <thead className="sticky top-0 z-10 bg-[var(--color-surface)]">
                <tr className="border-b border-[var(--color-border)]">
                  <th className="w-4 px-4 py-2.5" />
                  <th className="px-3 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Finding</th>
                  <th className="px-3 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)] hidden md:table-cell">Scanner</th>
                  <th className="px-3 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)] hidden lg:table-cell">Repository</th>
                  <th className="px-3 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Chain</th>
                  <th className="px-3 py-2.5 text-right text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Risk</th>
                  <th
                    aria-sort={epssSort === "asc" ? "ascending" : epssSort === "desc" ? "descending" : "none"}
                    className="px-3 py-2.5 text-right text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)] hidden sm:table-cell"
                  >
                    <button
                      type="button"
                      onClick={toggleEpssSort}
                      className="inline-flex items-center gap-1 ml-auto text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:rounded"
                      title="Exploit Prediction Scoring System — sort by percentile"
                    >
                      EPSS
                      <span aria-hidden="true" className="text-[8px] leading-none">
                        {epssSort === "desc" ? "▼" : epssSort === "asc" ? "▲" : "↕"}
                      </span>
                    </button>
                  </th>
                  <th className="px-3 py-2.5 text-right text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)] hidden sm:table-cell">Age</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border-divider)]">
                {sorted.map((finding) => (
                  <tr
                    key={finding.id}
                    onClick={() => setSelectedFinding(finding)}
                    tabIndex={0}
                    role="button"
                    aria-label={`Open finding: ${finding.title}`}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault()
                        setSelectedFinding(finding)
                      }
                    }}
                    className={`cursor-pointer hover:bg-[var(--color-bg-hover)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset ${
                      selectedFinding?.id === finding.id ? "bg-[var(--color-nav-active)]" : ""
                    }`}
                  >
                    <td className="px-4 py-3">
                      <span
                        className="inline-block h-2 w-2 rounded-full"
                        style={{ background: SEV_COLOR[finding.severity] }}
                        aria-label={finding.severity}
                      />
                    </td>

                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-medium text-[var(--color-text-primary)] truncate max-w-[22rem]">
                          {finding.title}
                        </span>
                        {finding.cve && (
                          <span className="shrink-0 font-[family-name:var(--font-jetbrains-mono)] text-[11.5px] text-[var(--color-text-tertiary)]">
                            {finding.cve}
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="px-3 py-3 hidden md:table-cell">
                      <div className="flex items-center gap-2">
                        <span
                          className="inline-flex h-4 w-[2.4rem] items-center justify-center rounded text-[9px] font-bold"
                          style={{ background: SCANNER_BG[finding.scanner], color: SCANNER_FG[finding.scanner] }}
                        >
                          {SCANNER_LABEL[finding.scanner]}
                        </span>
                        {finding.filePath && (
                          <span className="hidden xl:block font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-tertiary)] truncate max-w-[14rem]">
                            {finding.filePath}
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="px-3 py-3 hidden lg:table-cell">
                      <span className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-secondary)] truncate max-w-[16rem]">
                        {finding.repo}
                      </span>
                    </td>

                    <td className="px-3 py-3">
                      <span className="text-[var(--color-text-tertiary)] text-xs">—</span>
                    </td>

                    <td className="px-3 py-3">
                      {finding.riskScore != null ? (
                        <RiskScoreCell score={finding.riskScore} argus={finding.riskScore >= 70} />
                      ) : (
                        <span className="text-[var(--color-text-tertiary)] text-xs text-right block">—</span>
                      )}
                    </td>

                    <td className="px-3 py-3 text-right hidden sm:table-cell">
                      <EpssScoreCell percentile={finding.epssPercentile} />
                    </td>

                    <td className="px-3 py-3 text-right hidden sm:table-cell">
                      <span className="text-xs text-[var(--color-text-tertiary)]">{finding.age}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="flex items-center justify-between border-t border-[var(--color-border)] px-4 py-2.5">
              <span className="text-xs text-[var(--color-text-secondary)]">
                Showing {sorted.length} of {totalCount} findings
              </span>
              {nextCursor && (
                <button
                  type="button"
                  onClick={handleLoadMore}
                  disabled={loadingMore}
                  className="rounded-md border border-[var(--color-border)] px-3 py-1 text-[11px] font-semibold text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-border-strong)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] disabled:opacity-50 transition-colors"
                >
                  {loadingMore ? "Loading…" : "Load more"}
                </button>
              )}
            </div>
          </>
        )}
      </div>

      <FindingsDrawerShell
        open={selectedFinding != null}
        onClose={() => setSelectedFinding(null)}
        label="Finding detail"
      >
        {selectedFinding && (
          <>
            <DrawerHeader
              eyebrow={`${SCANNER_LABEL[selectedFinding.scanner]} · ${selectedFinding.severity.toUpperCase()}`}
              title={selectedFinding.title}
              identifier={selectedFinding.cve ?? selectedFinding.filePath}
              onClose={() => setSelectedFinding(null)}
            />

            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              <DrawerSection label="Details">
                <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-[13px]">
                  <div>
                    <dt className="text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Severity</dt>
                    <dd className="mt-1 font-semibold" style={{ color: SEV_COLOR[selectedFinding.severity] }}>
                      {selectedFinding.severity.charAt(0).toUpperCase() + selectedFinding.severity.slice(1)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Scanner</dt>
                    <dd className="mt-1 text-[var(--color-text-primary)]">{SCANNER_LABEL[selectedFinding.scanner]}</dd>
                  </div>
                  <div>
                    <dt className="text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Repository</dt>
                    <dd className="mt-1 font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-primary)]">
                      {selectedFinding.repo}
                    </dd>
                  </div>
                  {selectedFinding.riskScore != null && (
                    <div>
                      <dt className="text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Risk Score</dt>
                      <dd className="mt-1">
                        <RiskScoreCell score={selectedFinding.riskScore} argus={selectedFinding.riskScore >= 70} />
                      </dd>
                    </div>
                  )}
                </dl>
              </DrawerSection>
            </div>
          </>
        )}
      </FindingsDrawerShell>
    </div>
  )
}
