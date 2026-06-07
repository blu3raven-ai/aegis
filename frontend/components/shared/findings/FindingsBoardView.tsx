"use client"

import { useState, useCallback, useEffect, useMemo, useRef, type ReactNode } from "react"
import { FindingsEmptyState } from "@/components/shared/FindingsEmptyState"
import { EmptyOverviewBanner, GhostPreviewWrapper } from "@/components/shared/EmptyOverviewBanner"
import { FindingsGhostPreview } from "@/components/shared/findings/FindingsGhostPreview"
import { DrawerHeader } from "@/components/shared/FindingDrawer/DrawerHeader"
import { DrawerSection } from "@/components/shared/FindingDrawer/DrawerSection"
import { RiskScoreCell } from "@/components/shared/chain/RiskScoreCell"
import { IntelLiveBanner } from "@/components/shared/chain/IntelLiveBanner"
import { useSSE } from "@/components/providers/SSEProvider"
import type { ArgusIntelPushEvent } from "@/lib/shared/sse-types"
import { ExportFindingsButton } from "@/components/shared/findings/ExportFindingsButton"
import { FindingsCommandBar } from "./FindingsCommandBar"
import type { GroupKey } from "./FindingsDisplayOverflow"
import { FindingsGroupHeader } from "./FindingsGroupHeader"
import { FindingRowTags } from "./FindingRowTags"
import { type SortKey } from "./FindingsSortDropdown"
import { presetToFirstSeenAfter, type AgePresetKey } from "./FindingsAgeFilter"
import { type FindingsMoreFiltersValues } from "./FindingsMoreFiltersPopover"
import { FindingsPagination } from "./FindingsPagination"
import { EpssScoreCell } from "@/components/shared/findings/EpssScoreCell"
import { FindingDetailActions } from "@/components/shared/findings/FindingDetailActions"
import { FindingAssigneeEditor } from "@/components/shared/findings/FindingAssigneeEditor"
import { FindingOriginSection } from "@/components/shared/findings/FindingOriginSection"
import { RecommendedFixSection } from "@/components/shared/findings/RecommendedFixSection"
import { PageHeader } from "@/components/layout/PageHeader"
import { KpiCard } from "@/components/shared/KpiCard"
import {
  DISMISS_REASONS,
  bulkDismissFindings,
  listFindings,
  listFindingsSummary,
  type DismissReason,
  type FindingScanner,
  type FindingState,
  type FindingsSummary,
} from "@/lib/client/findings-api"
import { listRepos, type RepoSummary } from "@/lib/client/repos-api"
import {
  mapApiFinding,
  type FindingRow as Finding,
  type FindingScanner as Scanner,
  type FindingSeverity as Severity,
} from "@/lib/shared/findings/row-mapper"

// ── Constants ────────────────────────────────────────────────────────────────

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"
const PAGE_SIZE = 25

const VALID_VIEW_KEYS = new Set<string>([
  "severity", "scanner", "state", "repo", "q", "collapsed",
  "sort", "age",
  "cwe", "kev", "epss_min", "risk_score_min", "assignee",
  "page",
])

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

const SCANNER_GROUP_LABEL: Record<Scanner, string> = {
  deps: "Dependencies",
  sast: "Code Scanning",
  containers: "Containers",
  secrets: "Secrets",
  iac: "Infrastructure as Code",
}

const SEVERITY_GROUP_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
}

// Stable ordering per group key keeps the visual scan rhythm consistent.
const SCANNER_ORDER: Scanner[] = ["deps", "sast", "secrets", "containers", "iac"]
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"]

const INITIAL_ROWS_PER_GROUP = 5

function groupKeyFor(row: Finding, key: GroupKey): string {
  switch (key) {
    case "scanner":
      return row.scanner
    case "severity":
      return row.severity
    case "repo":
      return row.repo || "Unassigned"
    case "status":
      return row.state ?? "unknown"
  }
}

function groupLabelFor(key: GroupKey, value: string): string {
  switch (key) {
    case "scanner":
      return SCANNER_GROUP_LABEL[value as Scanner] ?? value
    case "severity":
      return SEVERITY_GROUP_LABEL[value as Severity] ?? value
    case "status":
      return value.charAt(0).toUpperCase() + value.slice(1)
    case "repo":
      return value
  }
}

function compareGroupKeys(key: GroupKey, a: string, b: string): number {
  if (key === "scanner") {
    const ai = SCANNER_ORDER.indexOf(a as Scanner)
    const bi = SCANNER_ORDER.indexOf(b as Scanner)
    return (ai === -1 ? SCANNER_ORDER.length : ai) - (bi === -1 ? SCANNER_ORDER.length : bi)
  }
  if (key === "severity") {
    const ai = SEVERITY_ORDER.indexOf(a as Severity)
    const bi = SEVERITY_ORDER.indexOf(b as Severity)
    return (ai === -1 ? SEVERITY_ORDER.length : ai) - (bi === -1 ? SEVERITY_ORDER.length : bi)
  }
  return a.localeCompare(b)
}

function groupSeverityCounts(rows: Finding[]) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const r of rows) counts[r.severity] += 1
  return counts
}

// ── Component ─────────────────────────────────────────────────────────────────

export interface FindingsViewApi {
  applyView: (state: Record<string, string>) => void
  currentUrlState: Record<string, string>
  savedViewsRefreshSignal: number
  onSavedViewCreated: () => void
}

export interface FindingsBoardViewProps {
  pageTitle: string
  pageIcon: ReactNode
  /** Optional subtitle rendered under the title in the PageHeader. */
  pageDescription?: string
  /** Initial state filter applied on first mount. Pass undefined for a state-agnostic view. */
  initialStateFilter?: FindingState[]
  /**
   * Optional queue sidebar rendered to the left of the findings list. When passed as a
   * render-function, the sidebar receives the saved-views API and the header's
   * Views/Save/Manage controls are hidden (the sidebar owns them instead).
   */
  leftSidebar?: ReactNode | ((api: FindingsViewApi) => ReactNode)
  /** Show the KPI summary strip below the page header. Defaults to true; /inbox hides it to match the mock. */
  showSummaryStrip?: boolean
  /** Compact mock-style filter header inside the list pane instead of the wide filter bar. /inbox opts in. */
  compactHeader?: boolean
}

type ScannerFilter = FindingScanner | "all"

const SCANNER_FILTER_OPTIONS: { value: ScannerFilter; label: string }[] = [
  { value: "all",       label: "Tool: All" },
  { value: "deps",      label: "Tool: Dependencies" },
  { value: "sast",      label: "Tool: Code scanning" },
  { value: "secrets",   label: "Tool: Secrets" },
  { value: "container", label: "Tool: Container" },
  { value: "iac",       label: "Tool: IaC" },
]

type StateFilter = FindingState | "all"

const STATE_FILTER_OPTIONS: { value: StateFilter; label: string }[] = [
  { value: "all",       label: "State: All" },
  { value: "open",      label: "State: Open" },
  { value: "closed",    label: "State: Closed" },
  { value: "fixed",     label: "State: Fixed" },
  { value: "dismissed", label: "State: Dismissed" },
]

// Pick a single-value default from the initialStateFilter prop. The prop is
// kept as a list for backward-compat with callers (e.g. /inbox passing
// ["open"]); the in-page dropdown only supports one bucket at a time.
function initialStateFromProp(initial: FindingState[] | undefined): StateFilter {
  if (!initial || initial.length !== 1) return "all"
  return initial[0]
}

const VALID_SEVERITIES = new Set<Severity | "all">(["all", "critical", "high", "medium", "low"])
// Saved-view serialization uses the API-client scanner vocabulary ("container"),
// distinct from the row-mapper's "containers".
const VALID_SCANNERS = new Set<ScannerFilter>(["all", "deps", "container", "sast", "secrets", "iac"])
const VALID_STATES = new Set<StateFilter>(["all", "open", "closed", "fixed", "dismissed"])
const VALID_SORT_KEYS = new Set<SortKey>(["severity_age", "epss", "risk_score", "newest", "oldest"])
const VALID_AGE_PRESETS = new Set<AgePresetKey>(["any", "24h", "7d", "30d"])

const SEARCH_DEBOUNCE_MS = 250

function readFromSet<T extends string>(
  state: Record<string, string>,
  key: string,
  allowed: Set<T>,
  fallback: T,
): T {
  const raw = state[key]?.toLowerCase()
  if (raw && allowed.has(raw as T)) return raw as T
  return fallback
}

export function FindingsBoardView({ pageTitle, pageIcon, pageDescription, initialStateFilter, leftSidebar, showSummaryStrip = true, compactHeader = false }: FindingsBoardViewProps) {
  const sidebarOwnsSavedViews = typeof leftSidebar === "function"
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all")
  const [scannerFilter, setScannerFilter] = useState<ScannerFilter>("all")
  const [stateFilter, setStateFilter] = useState<StateFilter>(() => initialStateFromProp(initialStateFilter))
  const [repoFilter, setRepoFilter] = useState<string>("all")
  const [sortKey, setSortKey] = useState<SortKey>("severity_age")
  const [agePreset, setAgePreset] = useState<AgePresetKey>("any")
  const [moreFilters, setMoreFilters] = useState<FindingsMoreFiltersValues>({
    cwe: null,
    kev: false,
    epssMin: null,
    riskScoreMin: null,
    assigneeUserId: null,
  })
  const [page, setPage] = useState<number>(1)
  const [repoOptions, setRepoOptions] = useState<string[]>([])
  const [searchInput, setSearchInput] = useState("")
  const [searchQuery, setSearchQuery] = useState("")
  const [groupBy, setGroupBy] = useState<GroupKey>("scanner")
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(() => new Set<string>())
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const collapsedCsv = useMemo(
    () => Array.from(collapsedGroups).sort().join(","),
    [collapsedGroups],
  )
  const [findings, setFindings] = useState<Finding[]>([])
  const [totalCount, setTotalCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [selection, setSelection] = useState<ReadonlySet<string>>(() => new Set())
  const [intelMessage, setIntelMessage] = useState<string | null>(null)
  const [summary, setSummary] = useState<FindingsSummary | null>(null)
  const [savedRefreshSignal, setSavedRefreshSignal] = useState(0)
  const [staleViewKeys, setStaleViewKeys] = useState<string[]>([])
  const dismissedIntelRef = useRef(false)

  // Debounce the search input so we don't refetch on every keystroke.
  useEffect(() => {
    const trimmed = searchInput.trim()
    const id = setTimeout(() => setSearchQuery(trimmed), SEARCH_DEBOUNCE_MS)
    return () => clearTimeout(id)
  }, [searchInput])

  // Serialized view state — passed to the Save modal and persisted on the
  // backend. Keys mirror what FindingsBoardView reads in `applyView`.
  const currentUrlState: Record<string, string> = useMemo(() => {
    const params: Record<string, string> = {}
    if (sevFilter !== "all")             params.severity = sevFilter
    if (scannerFilter !== "all")         params.scanner = scannerFilter
    if (stateFilter !== "all")           params.state = stateFilter
    if (repoFilter !== "all")            params.repo = repoFilter
    if (searchQuery)                     params.q = searchQuery
    if (collapsedCsv)                    params.collapsed = collapsedCsv
    if (sortKey !== "severity_age")      params.sort = sortKey
    if (agePreset !== "any")             params.age = agePreset
    if (moreFilters.cwe)                 params.cwe = moreFilters.cwe
    if (moreFilters.kev)                 params.kev = "true"
    if (moreFilters.epssMin != null)     params.epss_min = String(moreFilters.epssMin)
    if (moreFilters.riskScoreMin != null) params.risk_score_min = String(moreFilters.riskScoreMin)
    if (moreFilters.assigneeUserId)      params.assignee = moreFilters.assigneeUserId
    if (page !== 1)                      params.page = String(page)
    return params
  }, [sevFilter, scannerFilter, stateFilter, repoFilter, searchQuery, collapsedCsv, sortKey, agePreset, moreFilters, page])

  function applyView(state: Record<string, string>) {
    const stale = Object.keys(state).filter((k) => !VALID_VIEW_KEYS.has(k))
    setStaleViewKeys(stale)
    setSevFilter(readFromSet<Severity | "all">(state, "severity", VALID_SEVERITIES, "all"))
    setScannerFilter(readFromSet<ScannerFilter>(state, "scanner", VALID_SCANNERS, "all"))
    setStateFilter(readFromSet<StateFilter>(state, "state", VALID_STATES, "all"))
    setRepoFilter(state.repo || "all")
    const q = state.q || ""
    setSearchInput(q)
    setSearchQuery(q)
    setCollapsedGroups(new Set((state.collapsed || "").split(",").filter(Boolean)))
    setSortKey(readFromSet<SortKey>(state, "sort", VALID_SORT_KEYS, "severity_age"))
    setAgePreset(readFromSet<AgePresetKey>(state, "age", VALID_AGE_PRESETS, "any"))
    setMoreFilters({
      cwe: state.cwe || null,
      kev: state.kev === "true",
      epssMin: state.epss_min ? Number(state.epss_min) : null,
      riskScoreMin: state.risk_score_min ? Number(state.risk_score_min) : null,
      assigneeUserId: state.assignee || null,
    })
    const nextPage = Number(state.page)
    setPage(Number.isFinite(nextPage) && nextPage > 0 ? nextPage : 1)
  }

  useEffect(() => {
    let cancelled = false
    listFindingsSummary(ORG_ID)
      .then((data) => { if (!cancelled) setSummary(data) })
      .catch(() => { if (!cancelled) setSummary(null) })
    return () => { cancelled = true }
  }, [])

  // Populate the Repo dropdown from the same /repos endpoint used by the
  // Repositories page. Best-effort — leaves the dropdown empty on failure.
  useEffect(() => {
    let cancelled = false
    listRepos({ limit: 200 })
      .then((rows: RepoSummary[]) => {
        if (cancelled) return
        const slugs = Array.from(new Set(rows.map((r) => `${r.org}/${r.repo}`))).sort()
        setRepoOptions(slugs)
      })
      .catch(() => { if (!cancelled) setRepoOptions([]) })
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (!selectedFinding) return
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") setSelectedFinding(null)
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [selectedFinding])

  useSSE("argus.intel_push", (data: ArgusIntelPushEvent) => {
    if (!dismissedIntelRef.current) {
      setIntelMessage(data.message ?? "New Argus intel available — chain risk scores updated.")
    }
  })

  const handleIntelDismiss = useCallback(() => {
    dismissedIntelRef.current = true
    setIntelMessage(null)
  }, [])

  const load = useCallback(async (
    severity: Severity | "all",
    scanner: ScannerFilter,
    q: string,
    repo: string,
    state: StateFilter,
    sort: SortKey,
    age: AgePresetKey,
    pageNum: number,
  ) => {
    setLoading(true)
    setError(null)
    try {
      const firstSeenAfter = presetToFirstSeenAfter(age)
      const resp = await listFindings({
        orgId: ORG_ID,
        limit: PAGE_SIZE,
        page: pageNum,
        sort,
        ...(severity !== "all" ? { severity: [severity] } : {}),
        ...(scanner !== "all" ? { scanner: [scanner] } : {}),
        ...(q ? { q } : {}),
        ...(repo !== "all" ? { repo } : {}),
        ...(state !== "all" ? { state: [state] } : {}),
        ...(firstSeenAfter ? { first_seen_after: firstSeenAfter } : {}),
        ...(moreFilters.cwe ? { cwe: moreFilters.cwe } : {}),
        ...(moreFilters.kev ? { kev: true } : {}),
        ...(moreFilters.epssMin != null ? { epss_min: moreFilters.epssMin } : {}),
        ...(moreFilters.riskScoreMin != null ? { risk_score_min: moreFilters.riskScoreMin } : {}),
        ...(moreFilters.assigneeUserId ? { assignee: moreFilters.assigneeUserId } : {}),
      })
      setFindings(resp.findings.map(mapApiFinding))
      setTotalCount(resp.total_count)
    } catch {
      setError("Failed to load findings. Please try again.")
      setFindings([])
      setTotalCount(0)
    } finally {
      setLoading(false)
    }
  }, [moreFilters])

  // Reset to page 1 whenever any filter changes so users don't land on an
  // empty page-3-of-2-results when they narrow the query.
  useEffect(() => {
    setPage(1)
  }, [sevFilter, scannerFilter, stateFilter, repoFilter, searchQuery, sortKey, agePreset, moreFilters])

  useEffect(() => {
    void load(sevFilter, scannerFilter, searchQuery, repoFilter, stateFilter, sortKey, agePreset, page)
  }, [sevFilter, scannerFilter, searchQuery, repoFilter, stateFilter, sortKey, agePreset, moreFilters, page, load])

  const handleRetry = useCallback(() => {
    void load(sevFilter, scannerFilter, searchQuery, repoFilter, stateFilter, sortKey, agePreset, page)
  }, [load, sevFilter, scannerFilter, searchQuery, repoFilter, stateFilter, sortKey, agePreset, page])

  const filtered = findings

  // Server-side sort (severity_age / epss / newest / oldest) drives row order.
  const sorted = filtered

  const toggleSelect = useCallback((id: string) => {
    setSelection((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const clearSelection = useCallback(() => setSelection(new Set()), [])

  const groups = useMemo(() => {
    const buckets = new Map<string, Finding[]>()
    for (const row of sorted) {
      const key = groupKeyFor(row, groupBy)
      const bucket = buckets.get(key)
      if (bucket) bucket.push(row)
      else buckets.set(key, [row])
    }
    return Array.from(buckets.entries())
      .sort(([a], [b]) => compareGroupKeys(groupBy, a, b))
      .map(([key, rows]) => ({ key, label: groupLabelFor(groupBy, key), rows }))
  }, [sorted, groupBy])

  const showEmpty = !loading && !error && sorted.length === 0
  const showTable = !loading && !error && sorted.length > 0

  // "No data at all" trigger for the ghost preview: empty result set AND every
  // filter is at its default. We honour the page-level initialStateFilter prop
  // so /inbox (default stateFilter "open") still counts as default.
  const defaultState = initialStateFromProp(initialStateFilter)
  const hasNoFilters =
    sevFilter === "all" &&
    scannerFilter === "all" &&
    repoFilter === "all" &&
    stateFilter === defaultState &&
    searchQuery === "" &&
    agePreset === "any" &&
    moreFilters.cwe === null &&
    moreFilters.kev === false &&
    moreFilters.epssMin === null &&
    moreFilters.riskScoreMin === null &&
    moreFilters.assigneeUserId === null
  const showGhostPreview =
    showEmpty && hasNoFilters && totalCount === 0

  return (
    <div className="flex h-full flex-col overflow-hidden bg-[var(--color-bg)]">
      <IntelLiveBanner message={intelMessage} onDismiss={handleIntelDismiss} />

      <PageHeader
        icon={pageIcon}
        title={pageTitle}
        description={pageDescription ?? "Unified cross-scanner findings with Argus risk scoring."}
        count={totalCount}
        controls={
          sidebarOwnsSavedViews ? null : (
            <ExportFindingsButton
              filters={{
                ...(sevFilter !== "all" ? { severity: sevFilter } : {}),
                ...(scannerFilter !== "all" ? { scanner: scannerFilter } : {}),
                ...(repoFilter !== "all" ? { repo_id: repoFilter } : {}),
              }}
            />
          )
        }
      />

      {staleViewKeys.length > 0 && (
        <div
          role="status"
          className="border-b border-[var(--color-verdict-uncertain-border)] bg-[var(--color-verdict-uncertain-subtle)] px-6 py-2 text-2xs text-[var(--color-verdict-uncertain)]"
        >
          This view referenced {staleViewKeys.length} stale {staleViewKeys.length === 1 ? "filter" : "filters"} ({staleViewKeys.join(", ")}) — they were skipped.
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">
        {sidebarOwnsSavedViews
          ? (leftSidebar as (api: FindingsViewApi) => ReactNode)({
              applyView,
              currentUrlState,
              savedViewsRefreshSignal: savedRefreshSignal,
              onSavedViewCreated: () => setSavedRefreshSignal((n) => n + 1),
            })
          : leftSidebar}
        <div className="flex flex-1 min-w-0 flex-col overflow-hidden">
        <div className="flex-1 overflow-auto">
        {showSummaryStrip && <FindingsSummaryStrip summary={summary} loading={summary === null && loading} />}

        <div className="border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-2.5">
          <FindingsCommandBar
            severity={sevFilter}
            scanner={scannerFilter}
            repo={repoFilter}
            state={stateFilter}
            moreFilters={moreFilters}
            onSeverityChange={(next) => setSevFilter(next as Severity | "all")}
            onScannerChange={(next) => setScannerFilter(next as ScannerFilter)}
            onRepoChange={setRepoFilter}
            onStateChange={(next) => setStateFilter(next as StateFilter)}
            onMoreFiltersChange={(patch) =>
              setMoreFilters((prev) => ({ ...prev, ...patch }))
            }
            searchInput={searchInput}
            onSearchInputChange={setSearchInput}
            onSearchSubmit={() => setSearchQuery(searchInput.trim())}
            searchQuery={searchQuery}
            onSearchClear={() => {
              setSearchInput("")
              setSearchQuery("")
            }}
            groupBy={groupBy}
            sortKey={sortKey}
            agePreset={agePreset}
            onGroupByChange={setGroupBy}
            onSortKeyChange={setSortKey}
            onAgePresetChange={setAgePreset}
            repoOptions={repoOptions}
          />
        </div>

        {loading && (
          <div className="divide-y divide-[var(--color-border-divider)]" aria-hidden="true">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-3">
                <span className="h-2 w-2 shrink-0 rounded-full bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
                <div className="h-3 w-[40%] rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
                <div className="ml-auto h-3 w-12 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse hidden md:block" />
                <div className="h-3 w-24 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse hidden lg:block" />
                <div className="h-3 w-10 rounded bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
              </div>
            ))}
          </div>
        )}

        {error && (
          <div className="flex items-center justify-between border-b border-[var(--color-border-divider)] px-5 py-3 text-xs text-[var(--color-severity-high)]">
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

        {showGhostPreview ? (
          <div className="space-y-4 px-5 py-4">
            <EmptyOverviewBanner />
            <GhostPreviewWrapper>
              <FindingsGhostPreview />
            </GhostPreviewWrapper>
          </div>
        ) : showEmpty ? (
          <FindingsEmptyState
            message={
              sevFilter !== "all"
                ? `No ${sevFilter} findings.`
                : "No findings yet. Connect a source to start scanning."
            }
            onClearFilters={
              sevFilter !== "all" ? () => setSevFilter("all") : undefined
            }
          />
        ) : null}

        {showTable && compactHeader && (
          <>
            {selection.size > 0 && (
              <BulkActionBar
                ids={Array.from(selection).map(Number).filter(Number.isFinite)}
                onClear={clearSelection}
                onDismissed={() => {
                  // Refetch to drop the now-dismissed rows.
                  void load(sevFilter, scannerFilter, searchQuery, repoFilter, stateFilter, sortKey, agePreset, page)
                  clearSelection()
                }}
              />
            )}
            <div className="divide-y divide-[var(--color-border)]">
              {groups.map((group) => (
                <div key={`${groupBy}:${group.key}`}>
                  <FindingsGroupHeader
                    label={group.label}
                    severityCounts={groupSeverityCounts(group.rows)}
                    total={group.rows.length}
                    expanded={!collapsedGroups.has(group.key)}
                    onToggle={() => {
                      setCollapsedGroups((prev) => {
                        const next = new Set(prev)
                        if (next.has(group.key)) next.delete(group.key)
                        else next.add(group.key)
                        return next
                      })
                      setExpandedGroups((prev) => {
                        const next = new Set(prev); next.delete(group.key); return next
                      })
                    }}
                  />
                  {!collapsedGroups.has(group.key) && (() => {
                    const expanded = expandedGroups.has(group.key)
                    const visible = expanded ? group.rows : group.rows.slice(0, INITIAL_ROWS_PER_GROUP)
                    const hiddenCount = group.rows.length - INITIAL_ROWS_PER_GROUP
                    return (
                      <>
                        {visible.map((finding) => (
                          <CompactFindingRow
                            key={finding.id}
                            finding={finding}
                            selected={selection.has(finding.id)}
                            onToggleSelect={() => toggleSelect(finding.id)}
                            onOpen={() => setSelectedFinding(finding)}
                            active={selectedFinding?.id === finding.id}
                          />
                        ))}
                        {!expanded && hiddenCount > 0 && (
                          <div
                            onClick={() => setExpandedGroups((prev) => {
                              const next = new Set(prev); next.add(group.key); return next
                            })}
                            onKeyDown={(e) => {
                              if (e.key === "Enter" || e.key === " ") {
                                e.preventDefault()
                                setExpandedGroups((prev) => {
                                  const next = new Set(prev); next.add(group.key); return next
                                })
                              }
                            }}
                            tabIndex={0}
                            role="button"
                            aria-label={`Show ${hiddenCount} more findings in ${group.label}`}
                            className="cursor-pointer px-4 py-2 text-center text-xs text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset"
                          >
                            {`Show ${group.rows.length - INITIAL_ROWS_PER_GROUP} more ${group.label.toLowerCase()} →`}
                          </div>
                        )}
                      </>
                    )
                  })()}
                </div>
              ))}
            </div>

            <FindingsPagination
              page={page}
              pageSize={PAGE_SIZE}
              total={totalCount}
              onChange={setPage}
            />
          </>
        )}

        {showTable && !compactHeader && (
          <>
            <table className="w-full border-collapse text-sm">
              <thead className="sticky top-0 z-10 bg-[var(--color-surface)]">
                <tr className="border-b border-[var(--color-border)]">
                  <th className="w-4 px-4 py-2.5" />
                  <th className="px-3 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Finding</th>
                  <th className="px-3 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)] hidden md:table-cell">Scanner</th>
                  <th className="px-3 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)] hidden lg:table-cell">Repository</th>
                  <th className="px-3 py-2.5 text-left text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Chain</th>
                  <th className="px-3 py-2.5 text-right text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Risk</th>
                  <th className="px-3 py-2.5 text-right text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)] hidden sm:table-cell">
                    EPSS
                  </th>
                  <th className="px-3 py-2.5 text-right text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)] hidden sm:table-cell">Age</th>
                </tr>
              </thead>
              {groups.map((group) => (
                <tbody key={`${groupBy}:${group.key}`} className="divide-y divide-[var(--color-border-divider)]">
                  <tr className="bg-[var(--color-bg-section)]">
                    <td colSpan={8} className="px-0 py-0">
                      <FindingsGroupHeader
                        label={group.label}
                        severityCounts={groupSeverityCounts(group.rows)}
                        total={group.rows.length}
                        expanded={!collapsedGroups.has(group.key)}
                        onToggle={() => {
                          setCollapsedGroups((prev) => {
                            const next = new Set(prev)
                            if (next.has(group.key)) next.delete(group.key)
                            else next.add(group.key)
                            return next
                          })
                          setExpandedGroups((prev) => {
                            const next = new Set(prev); next.delete(group.key); return next
                          })
                        }}
                      />
                    </td>
                  </tr>
                  {!collapsedGroups.has(group.key) && (() => {
                    const expanded = expandedGroups.has(group.key)
                    const visible = expanded ? group.rows : group.rows.slice(0, INITIAL_ROWS_PER_GROUP)
                    const hiddenCount = group.rows.length - INITIAL_ROWS_PER_GROUP
                    return (
                      <>
                        {visible.map((finding) => (
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
                                <FindingRowTags
                                  kev={finding.kev}
                                  epssPercentile={finding.epssPercentile}
                                  firstSeen={finding.firstSeen}
                                  cwe={finding.cwe}
                                />
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
                        {!expanded && hiddenCount > 0 && (
                          <tr
                            onClick={() => setExpandedGroups((prev) => {
                              const next = new Set(prev); next.add(group.key); return next
                            })}
                            onKeyDown={(e) => {
                              if (e.key === "Enter" || e.key === " ") {
                                e.preventDefault()
                                setExpandedGroups((prev) => {
                                  const next = new Set(prev); next.add(group.key); return next
                                })
                              }
                            }}
                            tabIndex={0}
                            role="button"
                            aria-label={`Show ${hiddenCount} more findings in ${group.label}`}
                            className="cursor-pointer text-xs text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset"
                          >
                            <td colSpan={8} className="px-4 py-2 text-center">
                              {`Show ${group.rows.length - INITIAL_ROWS_PER_GROUP} more ${group.label.toLowerCase()} →`}
                            </td>
                          </tr>
                        )}
                      </>
                    )
                  })()}
                </tbody>
              ))}
            </table>

            <FindingsPagination
              page={page}
              pageSize={PAGE_SIZE}
              total={totalCount}
              onChange={setPage}
            />
          </>
        )}
        </div>
        </div>

        {selectedFinding && (
          <aside
            aria-label="Finding detail"
            className="hidden lg:flex w-[380px] shrink-0 flex-col border-l border-[var(--color-border)] bg-[var(--color-surface)] overflow-hidden"
          >
            <DrawerHeader
              eyebrow={`${selectedFinding.severity.charAt(0).toUpperCase()}${selectedFinding.severity.slice(1)} · ${SCANNER_GROUP_LABEL[selectedFinding.scanner]}`}
              eyebrowDotColor={SEV_COLOR[selectedFinding.severity]}
              title={selectedFinding.title}
              identifier={selectedFinding.cve ?? selectedFinding.filePath}
              badges={<FindingDetailBadges finding={selectedFinding} />}
              onClose={() => setSelectedFinding(null)}
            />

            <FindingDetailActions />

            <div className="flex-1 overflow-y-auto p-5 space-y-6">
              <DrawerSection label="Details">
                <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
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
                  <div className="col-span-2">
                    <dt className="text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Assignee</dt>
                    <dd className="mt-1">
                      <FindingAssigneeEditor
                        findingId={selectedFinding.id}
                        currentAssignee={selectedFinding.assigneeUserId ?? null}
                        onUpdate={(next) => {
                          setSelectedFinding((curr) =>
                            curr && curr.id === selectedFinding.id
                              ? { ...curr, assigneeUserId: next ?? undefined }
                              : curr,
                          )
                          setFindings((rows) =>
                            rows.map((r) =>
                              r.id === selectedFinding.id
                                ? { ...r, assigneeUserId: next ?? undefined }
                                : r,
                            ),
                          )
                        }}
                      />
                    </dd>
                  </div>
                </dl>
              </DrawerSection>

              <FindingOriginSection
                finding={selectedFinding}
                scannerLabel={SCANNER_LABEL[selectedFinding.scanner]}
              />

              <RecommendedFixSection fix={selectedFinding.recommendedFix} />

              <ActivityTimelineSection finding={selectedFinding} scannerLabel={SCANNER_LABEL[selectedFinding.scanner]} />
            </div>
          </aside>
        )}
      </div>
    </div>
  )
}

const NEUTRAL = "text-[var(--color-text-primary)]"
const CRITICAL = "text-[var(--color-severity-critical)]"
const WARN = "text-[var(--color-severity-high)]"
const OK = "text-[var(--color-state-fixed)]"

// ── Compact finding row + bulk action bar ────────────────────────────────────

function statusPillLabel(state: string | undefined): string {
  switch (state) {
    case "open":
      return "New"
    case "fixed":
      return "Fixed"
    case "dismissed":
      return "Dismissed"
    case "closed":
      return "Closed"
    default:
      return "New"
  }
}

function statusToneClass(state: string | undefined): string {
  switch (state) {
    case "open":
      return "bg-[color-mix(in_srgb,#a78bfa_18%,transparent)] text-[#a78bfa]"
    case "fixed":
      return "bg-[color-mix(in_srgb,var(--color-state-fixed)_18%,transparent)] text-[var(--color-state-fixed)]"
    case "dismissed":
      return "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
    case "closed":
      return "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
    default:
      return "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
  }
}

function CompactFindingRow({
  finding,
  selected,
  onToggleSelect,
  onOpen,
  active,
}: {
  finding: Finding
  selected: boolean
  onToggleSelect: () => void
  onOpen: () => void
  active: boolean
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={`Open finding: ${finding.title}`}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault()
          onOpen()
        }
      }}
      className={`relative grid cursor-pointer grid-cols-[18px_auto_minmax(0,1fr)_auto_auto] items-center gap-3 px-4 py-2.5 border-b border-[var(--color-border-divider)] transition-colors hover:bg-[var(--color-surface)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset ${
        active
          ? "bg-[var(--color-surface-raised)] before:absolute before:left-0 before:top-0 before:bottom-0 before:w-[2px] before:bg-[var(--color-accent)]"
          : selected
            ? "bg-[var(--color-accent-subtle)]"
            : ""
      }`}
    >
      <span
        onClick={(e) => { e.stopPropagation(); onToggleSelect() }}
        onKeyDown={(e) => { if (e.key === " " || e.key === "Enter") { e.stopPropagation() } }}
        className="flex items-center justify-center"
      >
        <input
          type="checkbox"
          checked={selected}
          onChange={onToggleSelect}
          onClick={(e) => e.stopPropagation()}
          aria-label={`Select ${finding.title}`}
          className="h-3.5 w-3.5 accent-[var(--color-accent)] cursor-pointer"
        />
      </span>

      <span
        className="h-2 w-2 shrink-0 rounded-full"
        style={{ background: SEV_COLOR[finding.severity] }}
        aria-label={finding.severity}
      />

      <div className="min-w-0">
        <div className="flex items-center gap-2 min-w-0">
          <span className="truncate text-[13px] font-medium text-[var(--color-text-primary)]">
            {finding.title}
          </span>
          <FindingRowTags
            kev={finding.kev}
            epssPercentile={finding.epssPercentile}
            firstSeen={finding.firstSeen}
            cwe={finding.cwe}
          />
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-tertiary)]">
          {finding.repo && <span className="truncate">{finding.repo}</span>}
          {finding.filePath && <span className="truncate">{finding.filePath}</span>}
          {finding.cve && <span className="text-[var(--color-text-tertiary)]">{finding.cve}</span>}
        </div>
      </div>

      <span
        className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider ${statusToneClass(finding.state)}`}
      >
        {statusPillLabel(finding.state)}
      </span>

      <span className="shrink-0 min-w-[2rem] text-right tabular-nums text-[11px] text-[var(--color-text-tertiary)]">
        {finding.age}
      </span>
    </div>
  )
}

function BulkActionBar({
  ids,
  onClear,
  onDismissed,
}: {
  ids: number[]
  onClear: () => void
  onDismissed: () => void
}) {
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const count = ids.length

  async function handleDismiss(reason: DismissReason) {
    if (ids.length === 0 || submitting) return
    setSubmitting(true)
    setError(null)
    try {
      await bulkDismissFindings(ids, reason)
      onDismissed()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Dismiss failed")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-t border-[var(--color-accent)]/30 bg-[color-mix(in_srgb,var(--color-accent)_8%,transparent)] px-4 py-2 text-[13px]">
      <span aria-hidden="true" className="text-[var(--color-accent)]">
        <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
          <polyline points="20 6 9 17 4 12" />
        </svg>
      </span>
      <span className="text-[var(--color-text-primary)]">
        <span className="font-semibold text-[var(--color-accent)]">{count}</span> selected
      </span>
      <button
        type="button"
        onClick={onClear}
        disabled={submitting}
        className="text-[12px] text-[var(--color-text-tertiary)] hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] rounded disabled:opacity-50"
      >
        Clear
      </button>
      {error && (
        <span className="text-[12px] text-[var(--color-severity-high)]" role="alert">
          {error}
        </span>
      )}
      <div className="ml-auto flex items-center gap-1.5">
        <label className="relative inline-flex">
          <span
            className={`inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-2.5 py-1 text-[12px] font-medium text-[var(--color-text-primary)] focus-within:ring-2 focus-within:ring-[var(--color-accent)] ${
              submitting ? "opacity-50 cursor-not-allowed" : "cursor-pointer hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
            }`}
          >
            <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
            </svg>
            {submitting ? "Dismissing…" : "Dismiss with reason"}
          </span>
          <select
            value=""
            onChange={(e) => {
              const v = e.target.value as DismissReason | ""
              if (v) void handleDismiss(v)
              e.target.value = ""
            }}
            disabled={submitting}
            aria-label="Dismiss reason"
            className="absolute inset-0 cursor-pointer opacity-0 disabled:cursor-not-allowed"
          >
            <option value="" disabled>
              Pick a reason
            </option>
            {DISMISS_REASONS.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>
      </div>
    </div>
  )
}

// ── Detail-pane activity timeline ────────────────────────────────────────────

function formatTimelineDate(iso: string | undefined): string {
  if (!iso) return ""
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ""
  const diff = Date.now() - d.getTime()
  const days = Math.floor(diff / 86_400_000)
  if (days <= 0) return "today"
  if (days === 1) return "yesterday"
  if (days < 30) return `${days} days ago`
  const months = Math.floor(days / 30)
  return `${months} month${months === 1 ? "" : "s"} ago`
}

function ActivityTimelineSection({ finding, scannerLabel }: { finding: Finding; scannerLabel: string }) {
  // Items are derived from finding fields we already have. When backend events
  // (assignment, comments, status changes) land, append them here.
  const items = [
    finding.introducedByCommit && {
      icon: (
        <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="3" />
          <path d="M4 9v6a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9" />
        </svg>
      ),
      body: (
        <>
          Introduced by <span className="font-[family-name:var(--font-jetbrains-mono)] text-[12px] text-[var(--color-text-primary)]">{finding.introducedByCommit.slice(0, 7)}</span>
          {finding.introducedByAuthor && (
            <> · <span className="text-[var(--color-text-primary)]">{finding.introducedByAuthor}</span></>
          )}
        </>
      ),
      time: formatTimelineDate(finding.firstSeen),
    },
    finding.firstSeen && {
      icon: (
        <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <path d="M12 8v4M12 16h.01" />
        </svg>
      ),
      body: (
        <>
          Detected by <span className="text-[var(--color-text-secondary)]">{scannerLabel}</span> scan
        </>
      ),
      time: formatTimelineDate(finding.firstSeen),
    },
  ].filter(Boolean) as { icon: ReactNode; body: ReactNode; time: string }[]

  function postComment() {
    // No-op stub — wired once a comments endpoint exists.
    console.log("[finding-comment] posted")
  }

  return (
    <section aria-labelledby="finding-activity-title">
      <h3 id="finding-activity-title" className="text-base font-semibold text-[var(--color-text-primary)]">
        Activity
      </h3>

      <ol className="mt-3 space-y-3">
        {items.map((item, idx) => (
          <li key={idx} className="flex gap-3">
            <span className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-full bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]">
              {item.icon}
            </span>
            <div className="min-w-0">
              <div className="text-[13px] text-[var(--color-text-primary)]">{item.body}</div>
              {item.time && <div className="mt-0.5 text-[11px] text-[var(--color-text-tertiary)]">{item.time}</div>}
            </div>
          </li>
        ))}
        {items.length === 0 && (
          <li className="text-[12px] text-[var(--color-text-tertiary)]">No activity yet.</li>
        )}
      </ol>

      <div className="mt-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] p-2">
        <textarea
          placeholder="Add a comment, mention @teammate…"
          rows={2}
          className="w-full resize-none bg-transparent text-[13px] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:outline-none"
        />
        <div className="mt-1 flex justify-end">
          <button
            type="button"
            onClick={postComment}
            className="rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--color-text-primary)] hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
          >
            Add
          </button>
        </div>
      </div>
    </section>
  )
}

function FindingDetailBadges({ finding }: { finding: Finding }) {
  const epssPct = finding.epssPercentile != null ? Math.round(finding.epssPercentile * 100) : null
  const showAge = finding.age && finding.age !== "—"
  if (epssPct === null && !showAge) return null
  return (
    <>
      {epssPct !== null && (
        <span className="rounded px-2 py-0.5 text-[11px] font-medium text-[var(--color-severity-high)] bg-[color-mix(in_srgb,var(--color-severity-high)_12%,transparent)]">
          EPSS {epssPct}%
        </span>
      )}
      {showAge && (
        <span className="rounded px-2 py-0.5 text-[11px] font-medium text-[var(--color-text-secondary)] bg-[var(--color-surface-raised)]">
          {finding.age} old
        </span>
      )}
    </>
  )
}

function FindingsSummaryStrip({
  summary,
  loading,
}: {
  summary: FindingsSummary | null
  loading: boolean
}) {
  const placeholder = loading ? "Loading…" : "Stats unavailable"
  const isEmpty = summary === null

  const openValue = isEmpty ? "—" : summary.open.toLocaleString()
  const criticalValue = isEmpty ? "—" : summary.critical.toLocaleString()
  const highValue = isEmpty ? "—" : summary.high.toLocaleString()
  const fixedValue = isEmpty ? "—" : summary.fixed_recent.toLocaleString()
  const dismissedValue = isEmpty ? "—" : summary.dismissed.toLocaleString()
  const windowDays = summary?.fixed_window_days ?? 7

  return (
    <div className="grid grid-cols-2 gap-3 border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-4 sm:grid-cols-3 lg:grid-cols-5">
      <KpiCard
        label="Open"
        value={openValue}
        note={isEmpty ? placeholder : "Across all scanners"}
        valueClass={NEUTRAL}
      />
      <KpiCard
        label="Critical"
        value={criticalValue}
        note={isEmpty ? placeholder : summary.critical > 0 ? "Open critical findings" : "No criticals open"}
        valueClass={isEmpty ? NEUTRAL : summary.critical > 0 ? CRITICAL : OK}
      />
      <KpiCard
        label="High"
        value={highValue}
        note={isEmpty ? placeholder : summary.high > 0 ? "Open high findings" : "No highs open"}
        valueClass={isEmpty ? NEUTRAL : summary.high > 0 ? WARN : OK}
      />
      <KpiCard
        label="Resolved this week"
        value={fixedValue}
        note={isEmpty ? placeholder : `Fixed in last ${windowDays}d`}
        valueClass={isEmpty ? NEUTRAL : summary.fixed_recent > 0 ? OK : NEUTRAL}
      />
      <KpiCard
        label="Dismissed"
        value={dismissedValue}
        note={isEmpty ? placeholder : "Marked won't-fix or accepted risk"}
        valueClass={NEUTRAL}
      />
    </div>
  )
}
