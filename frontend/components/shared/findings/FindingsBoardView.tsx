"use client"

import { useState, useCallback, useEffect, useMemo, useRef, type ReactNode } from "react"
import { FindingsEmptyState } from "@/components/shared/FindingsEmptyState"
import { EmptyOverviewBanner, GhostPreviewWrapper } from "@/components/shared/EmptyOverviewBanner"
import { FindingsGhostPreview } from "@/components/shared/findings/FindingsGhostPreview"
import { DrawerHeader } from "@/components/shared/FindingDrawer/DrawerHeader"
import { DrawerStatusBanner } from "@/components/shared/FindingDrawer/DrawerStatusBanner"
import { DismissPopover } from "@/components/shared/FindingDrawer/DismissPopover"
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
import { Button } from "@/components/ui/Button"
import { Sheet, openSheetCount } from "@/components/ui/Sheet"
import { Skeleton } from "@/components/ui/Skeleton"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import { cn } from "@/lib/shared/utils"
import { FindingDetailActions } from "@/components/shared/findings/FindingDetailActions"
import { FindingAssigneeEditor } from "@/components/shared/findings/FindingAssigneeEditor"
import { FindingOriginSection } from "@/components/shared/findings/FindingOriginSection"
import { FindingAge } from "@/components/shared/findings/FindingAge"
import { CodePreviewSection } from "@/components/shared/findings/CodePreviewSection"
import { FindingDataFlowSection } from "@/components/shared/findings/FindingDataFlowSection"
import { ImpactCallout } from "@/components/shared/findings/EvidenceSection"
import {
  SummarySection,
  TechnicalDetailSection,
  AttackScenarioSection,
  ImpactSection,
  DistinctnessSection,
  NotesVerificationSection,
} from "@/components/shared/findings/FindingReportSections"
import { FindingAcceptRiskAction } from "@/components/shared/findings/FindingAcceptRiskAction"
import { SecretVerificationSection } from "@/components/shared/findings/SecretVerificationSection"
import { SecurityBriefSection } from "@/components/shared/findings/SecurityBriefSection"
import { ContainerImageSection } from "@/components/shared/findings/ContainerImageSection"
import { CweContextSection } from "@/components/shared/findings/CweContextSection"
import { cweInfo } from "@/lib/shared/findings/cwe-catalog"
import { severityContext } from "@/lib/shared/findings/severity-context"
import { triageSummary } from "@/lib/shared/findings/triage-summary"
import { BlastRadiusSection } from "@/components/shared/findings/BlastRadiusSection"
import { FindingReferencesSection } from "@/components/shared/findings/FindingReferencesSection"
import { RecommendedFixSection } from "@/components/shared/findings/RecommendedFixSection"
import { PageHeader } from "@/components/layout/PageHeader"
import { KpiCard } from "@/components/shared/KpiCard"
import {
  DISMISS_REASONS,
  bulkDismissFindings,
  reopenFinding,
  deferFinding,
  listFindingComments,
  addFindingComment,
  type FindingComment,
  type FindingAdvisory,
  getFindingDetail,
  getFindingAdvisory,
  listFindings,
  listFindingsSummary,
  type DismissReason,
  type FindingScanner,
  type FindingState,
  type FindingsSummary,
  type ListFindingsParams,
  type VerdictCounts,
} from "@/lib/client/findings-api"
import { AdvisoryHeader } from "@/components/shared/findings/AdvisoryHeader"
import { FindingPocSection } from "@/components/shared/findings/FindingPocSection"
import { FindingDrawerGroup } from "@/components/shared/findings/FindingDrawerGroup"
import { listRepos, type RepoSummary } from "@/lib/client/sources-api"
import { listSourceConnections } from "@/lib/client/source-connections-api"
import { EnableVerificationBanner } from "@/components/shared/findings/EnableVerificationBanner"
import { VerdictFilterChips } from "@/components/shared/findings/VerdictFilterChips"
import { VerdictBadge } from "@/components/shared/findings/VerdictBadge"
import { parseVerdictFilter, type VerdictFilter } from "@/lib/shared/findings/verdicts"
import {
  mapApiFinding,
  type FindingRow as Finding,
  type FindingScanner as Scanner,
  type FindingSeverity as Severity,
  type FindingActionBand,
} from "@/lib/shared/findings/row-mapper"
import { buildRepoFileUrl } from "@/lib/shared/findings/repo-link"


const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"
const PAGE_SIZE = 25

const VALID_VIEW_KEYS = new Set<string>([
  "severity", "scanner", "state", "repo", "q", "collapsed",
  "sort", "age",
  "cwe", "kev", "epss_min", "bands", "assignee", "verdict",
  "page",
])

// Filter keys mirrored to the URL by the standalone /findings route. Every key
// here is re-hydrated on mount (page.tsx → initial* props), so the URL only ever
// carries params that round-trip. `collapsed`/`page` are intentionally excluded.
const URL_SYNC_KEYS = [
  "severity", "scanner", "state", "repo", "q",
  "sort", "age", "cwe", "kev", "epss_min", "bands", "assignee", "verdict",
] as const

const SEV_COLOR: Record<Severity, string> = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
}

const SCANNER_LABEL: Record<Scanner, string> = {
  dependencies_scanning: "SCA",
  code_scanning: "SAST",
  container_scanning: "CONT",
  secret_scanning: "SEC",
  iac_scanning: "IaC",
  agent_scanning: "AGT",
}

// Drive the scanner badge palette from the registered theme tokens (which carry
// distinct light/dark values) rather than hardcoded dark-only hex, so the badges
// theme correctly. Referenced as CSS vars since they're applied via inline style.
const SCANNER_BG: Record<Scanner, string> = {
  dependencies_scanning: "var(--color-scanner-deps-bg)",
  code_scanning: "var(--color-scanner-sast-bg)",
  container_scanning: "var(--color-scanner-containers-bg)",
  secret_scanning: "var(--color-scanner-secrets-bg)",
  iac_scanning: "var(--color-scanner-iac-bg)",
  agent_scanning: "var(--color-scanner-agent-bg)",
}

const SCANNER_FG: Record<Scanner, string> = {
  dependencies_scanning: "var(--color-scanner-deps-fg)",
  code_scanning: "var(--color-scanner-sast-fg)",
  container_scanning: "var(--color-scanner-containers-fg)",
  secret_scanning: "var(--color-scanner-secrets-fg)",
  iac_scanning: "var(--color-scanner-iac-fg)",
  agent_scanning: "var(--color-scanner-agent-fg)",
}

const SCANNER_GROUP_LABEL: Record<Scanner, string> = {
  dependencies_scanning: "Dependencies",
  code_scanning: "Code Scanning",
  container_scanning: "Containers",
  secret_scanning: "Secrets",
  iac_scanning: "Infrastructure as Code",
  agent_scanning: "Agent Security",
}

const SEVERITY_GROUP_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
}

const ACTION_BAND_LABEL: Record<FindingActionBand, string> = {
  act: "Act",
  attend: "Attend",
  track: "Track",
}

const ACTION_BAND_COLOR: Record<FindingActionBand, string> = {
  act: "var(--color-severity-critical)",
  attend: "var(--color-accent)",
  track: "var(--color-text-tertiary)",
}

// Runner-derived reachability of the vulnerable symbol, shown as a triage
// signal: a reachable path raises exploitability, no detected path lowers it,
// unknown stays neutral. Glyph + label so the meaning never rests on colour.
const REACH_GLYPH_PROPS = {
  viewBox: "0 0 24 24",
  className: "h-3.5 w-3.5",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 2,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
}

const REACHABILITY_SIGNAL: Record<
  string,
  { tone: "danger" | "success" | "neutral"; label: string; title: string; glyph: ReactNode }
> = {
  reachable: {
    tone: "danger",
    label: "Reachable",
    title: "A call path reaches the vulnerable symbol — exploitable in this codebase",
    glyph: (
      <svg {...REACH_GLYPH_PROPS}>
        <path d="M3 12h12" />
        <path d="M12 7l5 5-5 5" />
      </svg>
    ),
  },
  no_path: {
    tone: "success",
    label: "Not reachable",
    title: "No call path reaches the vulnerable symbol — lower exploitation risk",
    glyph: (
      <svg {...REACH_GLYPH_PROPS}>
        <circle cx="12" cy="12" r="8" />
        <path d="M7 7l10 10" />
      </svg>
    ),
  },
  unknown: {
    tone: "neutral",
    label: "Reachability unknown",
    title: "Reachability could not be determined — treat as potentially reachable",
    glyph: (
      <svg {...REACH_GLYPH_PROPS}>
        <circle cx="12" cy="12" r="8" />
        <path d="M12 16v-4" />
        <path d="M12 8h.01" />
      </svg>
    ),
  },
}

/**
 * Passive triage badge for a finding's SSVC-style action band. Read-only —
 * mirrors the VerdictBadge in the Confidence column rather than the
 * interactive FilterChip.
 */
function ActionBandBadge({ band }: { band: FindingActionBand }) {
  const color = ACTION_BAND_COLOR[band]
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold"
      style={{ color, background: `color-mix(in srgb, ${color} 14%, transparent)` }}
      title={`Action band: ${ACTION_BAND_LABEL[band]}`}
    >
      {ACTION_BAND_LABEL[band]}
    </span>
  )
}

// Stable ordering per group key keeps the visual scan rhythm consistent.
const SCANNER_ORDER: Scanner[] = ["dependencies_scanning", "code_scanning", "secret_scanning", "container_scanning", "iac_scanning", "agent_scanning"]

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"]

const INITIAL_ROWS_PER_GROUP = 5

// EPSS percentile is a 0-1 fraction server-side; clamp an inbound deep-link
// value to that range so a hand-edited ?epss_min=90 stays sensible. Mirrors
// the backend clamp in findings/service.py.
function clampEpssFraction(value: number | undefined): number | null {
  if (value == null || !Number.isFinite(value)) return null
  return Math.min(Math.max(value, 0), 1)
}

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

// Combine the verdict tallies from each per-scanner fetch so the verdict-filter
// chips reflect the whole cross-scanner result set, not just one scanner.
function mergeVerdictCounts(
  a: VerdictCounts | undefined,
  b: VerdictCounts | undefined,
): VerdictCounts | undefined {
  if (!a) return b
  if (!b) return a
  return {
    total: a.total + b.total,
    confirmed: a.confirmed + b.confirmed,
    needs_verify: a.needs_verify + b.needs_verify,
    possible: a.possible + b.possible,
    ruled_out: a.ruled_out + b.ruled_out,
    legacy: a.legacy + b.legacy,
  }
}

// Run `fn` over `items` with at most `limit` in flight at once, preserving input
// order in the result. The per-scanner findings fetch uses this so the backend
// isn't hit with one heavy query per scanner simultaneously — under the GraphQL
// 5s query timeout, that contention could tip a data-bearing scanner's query
// over the limit. `fn` is expected to never reject (callers catch per item).
async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length)
  let next = 0
  async function worker(): Promise<void> {
    while (next < items.length) {
      const idx = next++
      results[idx] = await fn(items[idx])
    }
  }
  const workerCount = Math.min(Math.max(1, limit), items.length)
  await Promise.all(Array.from({ length: workerCount }, () => worker()))
  return results
}

// Heavy per-scanner page fetches run at most this many at a time.
const PER_SCANNER_FETCH_CONCURRENCY = 2


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
   * Initial scanner filter applied on first mount. Used by the scanner-led
   * landing routes (/code, /dependencies, /secrets, /iac, /containers) to
   * render a pre-narrowed view without polluting the URL with ?scanner=…
   */
  initialScannerFilter?: FindingScanner
  /**
   * Initial severity / repo filters applied on first mount, sourced from URL
   * query params (e.g. a posture tile linking to ?severity=critical&repo=…).
   * Both are validated/scoped exactly like every other filter: severity is
   * checked against the allowed set, and repo only ever narrows within the
   * caller's server-enforced asset scope — it can never widen it.
   */
  initialSeverityFilter?: string
  initialRepoFilter?: string
  /**
   * Whether to pre-filter to KEV-listed findings on first mount, sourced from
   * the `?kev=true` query param (e.g. a KEV-affected-repo notification link).
   * Narrows within the caller's server-enforced asset scope.
   */
  initialKevFilter?: boolean
  /**
   * Initial EPSS percentile floor on first mount, sourced from the
   * `?epss_min=<fraction>` query param (e.g. a posture High-EPSS tile linking
   * to ?epss_min=0.9). A 0-1 fraction; values outside that range are clamped
   * here and again server-side. Narrows within the caller's asset scope.
   */
  initialEpssMinFilter?: number
  /** Initial free-text search applied on first mount (e.g. an SBOM component
   * row linking to ?q=<package> to see that package's findings). */
  initialSearch?: string
  /**
   * Finding id to open in the drawer on first mount, sourced from the
   * `?finding=<id>` query param. Lets activity-feed, dashboard, and release
   * links deep-link straight to a finding's detail. The detail read is still
   * permission- and scope-enforced server-side, so an out-of-scope id resolves
   * to nothing rather than leaking.
   */
  initialFindingId?: string
  /**
   * Initial "more filters" and ordering applied on first mount, sourced from URL
   * query params so a shared/bookmarked link restores the full filter set (not
   * just the primary chips). Each is validated exactly like the primary filters:
   * cwe/assignee are free strings scoped server-side, bands is a CSV whitelisted
   * against the known action-band tokens, and sort/age fall back to their
   * defaults when absent or unrecognised.
   */
  initialCwe?: string
  initialBands?: string
  initialAssignee?: string
  initialSort?: string
  initialAge?: string
  initialVerdictFilter?: VerdictFilter
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
  /**
   * Render the findings as a flat queue rather than a grouped board.
   * /inbox uses this to behave like an email inbox (no scanner group
   * headers, no "show N more" collapse — every visible row renders). The
   * grouped view stays the canonical /findings shape. Defaults to false.
   */
  flat?: boolean
  /**
   * Suppress the built-in PageHeader. Used when the view is embedded under a
   * shared header that owns the title and tab navigation (e.g. the Inbox page
   * which stacks Findings and Activity tabs under one "Inbox" header).
   */
  hideHeader?: boolean
  /**
   * Restrict findings to these repos (each an Asset.display_name, e.g.
   * "github:acme/foo"). Used by the per-source Findings tab to scope to that
   * source's repositories. The repo dropdown still narrows within this scope.
   */
  scopeRepos?: string[]
  /**
   * Mirror the active filters + open drawer into the URL query string so the
   * view is shareable/bookmarkable and survives refresh. Only the standalone
   * /findings route opts in; embedded uses (e.g. /inbox/triage) must not, or
   * they would clobber their own URL.
   */
  syncUrl?: boolean
}

type ScannerFilter = FindingScanner | "all"

type StateFilter = FindingState | "all"

const STATE_FILTER_OPTIONS: { value: StateFilter; label: string }[] = [
  { value: "all",       label: "State: All" },
  { value: "open",      label: "State: Open" },
  { value: "closed",    label: "State: Closed" },
  { value: "fixed",     label: "State: Fixed" },
  { value: "dismissed", label: "State: Dismissed" },
  { value: "deferred",  label: "State: Deferred" },
]

// Pick a single-value default from the initialStateFilter prop. The prop is
// kept as a list for backward-compat with callers (e.g. /inbox passing
// ["open"]); the in-page dropdown only supports one bucket at a time.
function initialStateFromProp(initial: FindingState[] | undefined): StateFilter {
  if (!initial || initial.length !== 1) return "all"
  return initial[0]
}

const VALID_SEVERITIES = new Set<Severity | "all">(["all", "critical", "high", "medium", "low"])
// Saved-view serialization uses the canonical wire-level scanner names.
// Derived from SCANNER_ORDER so a newly added scanner (e.g. agent_scanning) can
// never be silently dropped from the accepted filter set again.
const VALID_SCANNERS = new Set<ScannerFilter>(["all", ...SCANNER_ORDER])
const VALID_STATES = new Set<StateFilter>(["all", "open", "closed", "fixed", "dismissed", "deferred"])
const VALID_SORT_KEYS = new Set<SortKey>(["severity_age", "epss", "cvss", "action_band", "newest", "oldest"])
const VALID_AGE_PRESETS = new Set<AgePresetKey>(["any", "24h", "7d", "30d", "90d"])

const SEARCH_DEBOUNCE_MS = 250

type SortDirection = "ascending" | "descending" | "none"

/**
 * Column header that drives the shared `sortKey` state. Renders a real
 * <button> (keyboard-reachable) inside the <th>, mirrors the active sort
 * onto `aria-sort` for screen readers, and shows a caret affordance so the
 * sort state is visible — not just available via the Sort dropdown.
 */
function SortableTh({
  label,
  direction,
  onClick,
  className,
}: {
  label: string
  direction: SortDirection
  onClick: () => void
  className?: string
}) {
  const active = direction !== "none"
  return (
    <Th aria-sort={direction} className={className}>
      <button
        type="button"
        onClick={onClick}
        className="group inline-flex items-center gap-1 uppercase tracking-[0.14em] transition-colors hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)] rounded-sm"
        aria-label={`Sort by ${label}`}
      >
        {label}
        <svg
          viewBox="0 0 12 12"
          aria-hidden="true"
          className={cn(
            "h-3 w-3 shrink-0 transition-opacity",
            active
              ? "text-[var(--color-accent)] opacity-100"
              : "opacity-0 group-hover:opacity-50",
          )}
        >
          {direction === "ascending" ? (
            <path d="M6 3.5 9 7.5H3z" fill="currentColor" />
          ) : (
            <path d="M6 8.5 3 4.5h6z" fill="currentColor" />
          )}
        </svg>
      </button>
    </Th>
  )
}

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

/**
 * Translate the active filter state into `listFindings` query params (minus
 * pagination). Shared by the main page fetch and the per-scanner tab-count
 * fetch so the two never drift — the tab counts always reflect the same
 * severity / state / repo / search / age / risk filters the list is showing.
 */
function buildListParams(args: {
  severity: Severity | "all"
  scanner: ScannerFilter
  q: string
  repo: string
  state: StateFilter
  sort: SortKey
  age: AgePresetKey
  verdict: VerdictFilter
  moreFilters: FindingsMoreFiltersValues
  scopeRepos?: string[]
}): ListFindingsParams {
  const { severity, scanner, q, repo, state, sort, age, verdict, moreFilters, scopeRepos } = args
  const firstSeenAfter = presetToFirstSeenAfter(age)
  return {
    orgId: ORG_ID,
    sort,
    ...(severity !== "all" ? { severity: [severity] } : {}),
    ...(scanner !== "all" ? { scanner: [scanner] } : {}),
    ...(q ? { q } : {}),
    // The repo dropdown narrows to one repo; otherwise fall back to the
    // per-source scope (if any). `repo` is a comma-separated display_name
    // list the backend matches with IN.
    ...(repo !== "all"
      ? { repo }
      : scopeRepos && scopeRepos.length
        ? { repo: scopeRepos.join(",") }
        : {}),
    ...(state !== "all" ? { state: [state] } : {}),
    ...(firstSeenAfter ? { first_seen_after: firstSeenAfter } : {}),
    ...(moreFilters.cwe ? { cwe: moreFilters.cwe } : {}),
    ...(moreFilters.kev ? { kev: true } : {}),
    ...(moreFilters.epssMin != null ? { epss_min: moreFilters.epssMin } : {}),
    ...(moreFilters.bands.length ? { bands: moreFilters.bands } : {}),
    ...(moreFilters.assigneeUserId ? { assignee: moreFilters.assigneeUserId } : {}),
    ...(verdict ? { verdict } : {}),
  }
}

export function FindingsBoardView({ pageTitle, pageIcon, pageDescription, initialStateFilter, initialScannerFilter, initialSeverityFilter, initialRepoFilter, initialKevFilter, initialEpssMinFilter, initialSearch, initialFindingId, initialCwe, initialBands, initialAssignee, initialSort, initialAge, initialVerdictFilter, leftSidebar, showSummaryStrip = true, compactHeader = false, flat = false, hideHeader = false, scopeRepos, syncUrl = false }: FindingsBoardViewProps) {
  const sidebarOwnsSavedViews = typeof leftSidebar === "function"
  // Severity is validated against the allowed set (invalid → "all"); repo is a
  // free string that the backend resolves within the caller's asset scope.
  const [sevFilter, setSevFilter] = useState<Severity | "all">(() =>
    readFromSet<Severity | "all">({ severity: initialSeverityFilter ?? "" }, "severity", VALID_SEVERITIES, "all"),
  )
  const [scannerFilter, setScannerFilter] = useState<ScannerFilter>(initialScannerFilter ?? "all")
  const [stateFilter, setStateFilter] = useState<StateFilter>(() => initialStateFromProp(initialStateFilter))
  const [repoFilter, setRepoFilter] = useState<string>(initialRepoFilter || "all")
  const [sortKey, setSortKey] = useState<SortKey>(() =>
    readFromSet<SortKey>({ sort: initialSort ?? "" }, "sort", VALID_SORT_KEYS, "severity_age"),
  )
  const [agePreset, setAgePreset] = useState<AgePresetKey>(() =>
    readFromSet<AgePresetKey>({ age: initialAge ?? "" }, "age", VALID_AGE_PRESETS, "any"),
  )
  const [moreFilters, setMoreFilters] = useState<FindingsMoreFiltersValues>({
    cwe: initialCwe || null,
    kev: Boolean(initialKevFilter),
    epssMin: clampEpssFraction(initialEpssMinFilter),
    // Whitelist band tokens exactly like applyView — the backend raises on
    // unknown bands, so a hand-edited ?bands=critical must never reach it.
    bands: initialBands
      ? (initialBands.split(",").filter((b) => b === "act" || b === "attend" || b === "track") as FindingActionBand[])
      : [],
    assigneeUserId: initialAssignee || null,
  })
  const [page, setPage] = useState<number>(1)
  const [repoOptions, setRepoOptions] = useState<string[]>([])
  const [hasSourceConnections, setHasSourceConnections] = useState<boolean | null>(null)
  const [searchInput, setSearchInput] = useState(initialSearch ?? "")
  const [searchQuery, setSearchQuery] = useState(initialSearch ?? "")
  const [groupBy, setGroupBy] = useState<GroupKey>("scanner")
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(() => new Set<string>())
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const collapsedCsv = useMemo(
    () => Array.from(collapsedGroups).sort().join(","),
    [collapsedGroups],
  )
  const [findings, setFindings] = useState<Finding[]>([])
  const [totalCount, setTotalCount] = useState(0)
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>(initialVerdictFilter ?? null)
  const [verdictCounts, setVerdictCounts] = useState<VerdictCounts | undefined>(undefined)
  // Per-scanner pagination: in the default scanner-grouped board each scanner
  // section paginates independently so a noisy scanner can't bury a quieter one
  // on a deep global page. `scannerPages` is scanner -> current page (default 1)
  // and `scannerTotals` is scanner -> total count from that scanner's fetch.
  const [scannerPages, setScannerPages] = useState<Record<string, number>>({})
  const [scannerTotals, setScannerTotals] = useState<Record<string, number>>({})
  const [verificationEnabled, setVerificationEnabled] = useState<boolean>(true)  // assume configured until known otherwise
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [advisory, setAdvisory] = useState<FindingAdvisory | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  // Surface fetch failures in the drawer rather than silently showing a
  // partial (lean) row — the analyst must know the detail is incomplete.
  const [detailError, setDetailError] = useState<string | null>(null)
  const [advisoryError, setAdvisoryError] = useState<string | null>(null)
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
    if (moreFilters.bands.length)        params.bands = moreFilters.bands.join(",")
    if (moreFilters.assigneeUserId)      params.assignee = moreFilters.assigneeUserId
    if (verdictFilter)                   params.verdict = verdictFilter
    if (page !== 1)                      params.page = String(page)
    return params
  }, [sevFilter, scannerFilter, stateFilter, repoFilter, searchQuery, collapsedCsv, sortKey, agePreset, moreFilters, verdictFilter, page])

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
    setVerdictFilter(parseVerdictFilter(state.verdict))
    setMoreFilters({
      cwe: state.cwe || null,
      kev: state.kev === "true",
      epssMin: state.epss_min ? Number(state.epss_min) : null,
      // Strictly whitelist band tokens: the backend raises on unknown bands, so a
      // hand-edited ?bands=critical must never reach it.
      bands: state.bands
        ? (state.bands.split(",").filter((b) => b === "act" || b === "attend" || b === "track") as FindingActionBand[])
        : [],
      assigneeUserId: state.assignee || null,
    })
    const nextPage = Number(state.page)
    setPage(Number.isFinite(nextPage) && nextPage > 0 ? nextPage : 1)
  }

  useEffect(() => {
    let cancelled = false
    listFindingsSummary()
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

  // Determine whether any source connection exists so the empty state can
  // distinguish "no source connected" from "source connected, no findings yet".
  useEffect(() => {
    let cancelled = false
    listSourceConnections()
      .then((result) => {
        if (cancelled) return
        setHasSourceConnections(result.ok ? result.data.connections.length > 0 : false)
      })
      .catch(() => { if (!cancelled) setHasSourceConnections(false) })
    return () => { cancelled = true }
  }, [])

  useSSE("argus.intel_push", (data: ArgusIntelPushEvent) => {
    if (!dismissedIntelRef.current) {
      setIntelMessage(data.message ?? "New Argus intel available — chain risk scores updated.")
    }
  })

  const handleIntelDismiss = useCallback(() => {
    dismissedIntelRef.current = true
    setIntelMessage(null)
  }, [])

  // The default scanner-grouped board (scanner grouping, no scanner narrowing,
  // not the flat inbox queue) paginates each scanner group independently — one
  // fetch per scanner, each with its own page — so a noisy scanner can't bury a
  // quieter one. Any other shape keeps the single global paginator.
  const perScannerMode = groupBy === "scanner" && !flat && scannerFilter === "all"

  const load = useCallback(async (
    severity: Severity | "all",
    scanner: ScannerFilter,
    q: string,
    repo: string,
    state: StateFilter,
    sort: SortKey,
    age: AgePresetKey,
    verdict: VerdictFilter,
    pageNum: number,
  ) => {
    setLoading(true)
    setError(null)
    try {
      if (perScannerMode) {
        // One page-sized fetch per scanner, each on its own page. Rows are
        // concatenated in SCANNER_ORDER; totals feed the per-group paginators
        // and their sum drives the header count + queue length.
        // Each scanner is fetched independently; a single scanner's query
        // failing must degrade to "that group is empty", not blank the whole
        // board (one rejected promise would otherwise fail the entire load).
        const results = await mapWithConcurrency(
          SCANNER_ORDER,
          PER_SCANNER_FETCH_CONCURRENCY,
          (s) =>
            listFindings({
              ...buildListParams({ severity, scanner: s, q, repo, state, sort, age, verdict, moreFilters, scopeRepos }),
              page: scannerPages[s] ?? 1,
              limit: PAGE_SIZE,
            })
              .then((r) => [s, r] as const)
              .catch(() => [s, null] as const),
        )
        // Only a wholesale failure (every scanner errored) is a real error.
        if (results.every(([, r]) => r === null)) {
          throw new Error("all per-scanner findings queries failed")
        }
        const rows: Finding[] = []
        const totals: Record<string, number> = {}
        let sum = 0
        let mergedVerdicts: VerdictCounts | undefined
        for (const [s, r] of results) {
          if (!r) {
            totals[s] = 0
            continue
          }
          for (const row of r.findings) rows.push(mapApiFinding(row))
          totals[s] = r.total_count
          sum += r.total_count
          mergedVerdicts = mergeVerdictCounts(mergedVerdicts, r.verdict_counts)
        }
        setFindings(rows)
        setScannerTotals(totals)
        setTotalCount(sum)
        setVerdictCounts(mergedVerdicts)
      } else {
        const resp = await listFindings({
          ...buildListParams({ severity, scanner, q, repo, state, sort, age, verdict, moreFilters, scopeRepos }),
          limit: PAGE_SIZE,
          page: pageNum,
        })
        setFindings(resp.findings.map(mapApiFinding))
        setTotalCount(resp.total_count)
        setVerdictCounts(resp.verdict_counts)
      }
    } catch {
      setError("Failed to load findings. Please try again.")
      setFindings([])
      setTotalCount(0)
      setVerdictCounts(undefined)
    } finally {
      setLoading(false)
    }
  }, [moreFilters, scopeRepos, perScannerMode, scannerPages])

  // Reset to page 1 whenever any filter changes so users don't land on an
  // empty page-3-of-2-results when they narrow the query.
  useEffect(() => {
    setPage(1)
    // Reset every scanner group back to its first page too, for the same reason.
    setScannerPages({})
    // Drop the multi-select too: ids selected under the old filter no longer map
    // to visible rows, so the bulk bar would otherwise act on off-screen findings.
    setSelection(new Set())
  }, [sevFilter, scannerFilter, stateFilter, repoFilter, searchQuery, sortKey, agePreset, moreFilters, verdictFilter])

  useEffect(() => {
    void load(sevFilter, scannerFilter, searchQuery, repoFilter, stateFilter, sortKey, agePreset, verdictFilter, page)
  }, [sevFilter, scannerFilter, searchQuery, repoFilter, stateFilter, sortKey, agePreset, moreFilters, verdictFilter, page, scannerPages, groupBy, load])

  // New findings land when a scan finishes ingesting, so refetch on scan
  // completion — otherwise the list sits stale until a manual reload. Each
  // scanner job completes independently, so the board fills in scanner-by-
  // scanner as the run progresses. load() keeps the current rows on screen
  // during the refetch (no skeleton flash), and useSSE always invokes the
  // latest closure so the current filters/page are used.
  useSSE("scan.completed", () => {
    void load(sevFilter, scannerFilter, searchQuery, repoFilter, stateFilter, sortKey, agePreset, verdictFilter, page)
  })

  // Mid-scan preview ingest and verdict updates emit findings.updated (no
  // completion semantics) — refetch on it too so unverified findings appear
  // right after the scan phase and their verdicts stream in during verification.
  useSSE("findings.updated", () => {
    void load(sevFilter, scannerFilter, searchQuery, repoFilter, stateFilter, sortKey, agePreset, verdictFilter, page)
  })

  // LLM verification status drives the banner + the drawer's locked preview.
  // A 404 means no config exists → verification off. A 403 (no manage_settings)
  // leaves the fail-safe default (on) so viewers aren't nagged to set it up.
  useEffect(() => {
    let cancelled = false
    fetch("/api/v1/settings/llm")
      .then((r) => {
        if (r.status === 404) return { enabled: false }
        return r.ok ? r.json() : null
      })
      .then((data) => {
        if (cancelled || !data) return
        setVerificationEnabled(Boolean(data.enabled))
      })
      .catch(() => {
        /* network errors leave the banner hidden — fail safe */
      })
    return () => {
      cancelled = true
    }
  }, [])

  const handleRetry = useCallback(() => {
    void load(sevFilter, scannerFilter, searchQuery, repoFilter, stateFilter, sortKey, agePreset, verdictFilter, page)
  }, [load, sevFilter, scannerFilter, searchQuery, repoFilter, stateFilter, sortKey, agePreset, verdictFilter, page])

  const filtered = findings

  // Server-side sort (severity_age / epss / newest / oldest) drives row order.
  const sorted = filtered

  // Step through the queue from inside the detail slide-over so triage flow
  // survives the modal scrim — no close/reopen between findings. At a page
  // boundary, change the page and select its boundary row once it loads
  // (pendingSelectRef), so navigation spans the whole queue, not one page.
  const pendingSelectRef = useRef<"first" | "last" | null>(null)
  const goToAdjacent = useCallback((delta: number) => {
    if (pendingSelectRef.current || loading) return
    const curr = selectedFinding
    if (!curr) return
    const idx = sorted.findIndex((f) => f.id === curr.id)
    if (idx === -1) return
    const next = idx + delta
    if (next >= 0 && next < sorted.length) {
      setSelectedFinding(sorted[next])
      return
    }
    // Per-scanner mode has no single global page (each group paginates on its
    // own), so the queue is just the visible union — clamp at its ends.
    if (perScannerMode) return
    if (delta > 0 && page * PAGE_SIZE < totalCount) {
      pendingSelectRef.current = "first"
      setPage((p) => p + 1)
    } else if (delta < 0 && page > 1) {
      pendingSelectRef.current = "last"
      setPage((p) => p - 1)
    }
  }, [selectedFinding, sorted, page, totalCount, loading, perScannerMode])

  // After a boundary-triggered page change finishes loading, select the row at
  // the boundary so navigation continues seamlessly into the new page.
  useEffect(() => {
    if (!pendingSelectRef.current || loading) return
    const target = pendingSelectRef.current === "first" ? sorted[0] : sorted[sorted.length - 1]
    pendingSelectRef.current = null
    if (target) setSelectedFinding(target)
  }, [sorted, loading])

  const selectedIndex = selectedFinding
    ? sorted.findIndex((f) => f.id === selectedFinding.id)
    : -1
  // Availability spans the whole queue. In the single-paginator modes that
  // queue stretches across pages (offset by the current page); in per-scanner
  // mode the queue is exactly the visible union, so position is the row index.
  const globalPos =
    selectedIndex >= 0
      ? perScannerMode
        ? selectedIndex
        : (page - 1) * PAGE_SIZE + selectedIndex
      : -1
  const queueTotal = perScannerMode ? sorted.length : totalCount
  const hasPrevFinding = globalPos > 0
  const hasNextFinding = globalPos >= 0 && globalPos < queueTotal - 1

  // Disposition the open finding: dismiss with a reason, drop it from the
  // queue, and advance to the next one so triage keeps moving.
  const [dismissing, setDismissing] = useState(false)
  const [deferring, setDeferring] = useState(false)
  const [reopening, setReopening] = useState(false)
  const [dismissError, setDismissError] = useState<string | null>(null)
  const handlePocGenerated = useCallback(
    (poc: { poc_script: string; poc_filename: string; poc_language: string }) => {
      setSelectedFinding((curr) =>
        curr
          ? {
              ...curr,
              verificationMetadata: {
                ...(curr.verificationMetadata ?? {}),
                poc_script: poc.poc_script,
                poc_filename: poc.poc_filename,
                poc_language: poc.poc_language,
              },
            }
          : curr,
      )
    },
    [],
  )
  const [lastDismissed, setLastDismissed] = useState<{ finding: Finding; index: number; verb: string } | null>(null)
  // A `?finding=<id>` deep link that resolved to nothing (deleted or out of scope).
  const [deepLinkMissing, setDeepLinkMissing] = useState(false)

  // The list row (GraphQL) is lean; fetch full detail on open and merge the
  // decision content the list omits (description, rule, remediation,
  // confidence, code snippet + highlight) onto the selected finding. Keyed on
  // the finding id so navigating between findings refetches, while the merge
  // (same id) does not re-trigger.
  const selectedId = selectedFinding?.id
  useEffect(() => {
    if (!selectedId) return
    const id = Number(selectedId)
    if (!Number.isFinite(id)) return
    let active = true
    setDetailLoading(true)
    setDetailError(null)
    getFindingDetail(id)
      .then((raw) => {
        if (!active) return
        const d = mapApiFinding(raw)
        setSelectedFinding((curr) =>
          curr && curr.id === selectedId
            ? {
                ...curr,
                package: d.package ?? curr.package,
                // Refresh state from the authoritative detail read so the
                // status banner reflects a change made since the list loaded.
                state: d.state ?? curr.state,
                title: d.title || curr.title,
                description: d.description ?? curr.description,
                rule: d.rule ?? curr.rule,
                remediation: d.remediation ?? curr.remediation,
                confidence: d.confidence ?? curr.confidence,
                cwe: d.cwe ?? curr.cwe,
                codeSnippet: d.codeSnippet ?? curr.codeSnippet,
                codeSnippetStartLine: d.codeSnippetStartLine ?? curr.codeSnippetStartLine,
                highlightStart: d.highlightStart ?? curr.highlightStart,
                highlightEnd: d.highlightEnd ?? curr.highlightEnd,
                recommendedFix: d.recommendedFix ?? curr.recommendedFix,
                codeFlows: d.codeFlows ?? curr.codeFlows,
                // Verification reasoning + reachability are detail-only fields,
                // absent from the lean list row — merge them in on open.
                evidence: d.evidence ?? curr.evidence,
                exploitChain: d.exploitChain ?? curr.exploitChain,
                verificationMetadata: d.verificationMetadata ?? curr.verificationMetadata,
                reachability: d.reachability ?? curr.reachability,
                secretDetector: d.secretDetector ?? curr.secretDetector,
                secretVerified: d.secretVerified ?? curr.secretVerified,
                containerImage: d.containerImage ?? curr.containerImage,
                alsoAffectsRepos: d.alsoAffectsRepos ?? curr.alsoAffectsRepos,
                introducedByCommit: d.introducedByCommit ?? curr.introducedByCommit,
                // Concrete repo URL (self-hosted hosts) is detail-only; needed
                // for the view-in-repo deep-link.
                repoHtmlUrl: d.repoHtmlUrl ?? curr.repoHtmlUrl,
              }
            : curr,
        )
      })
      .catch((e) => {
        if (active) setDetailError(e instanceof Error ? e.message : String(e))
      })
      // Guarded by `active` so a stale resolve can't clear loading for the
      // finding the user has since navigated to.
      .finally(() => { if (active) setDetailLoading(false) })
    return () => { active = false }
  }, [selectedId])

  // Advisory enrichment for the Security Brief — lazily fetched per finding and
  // cleared on navigation so the previous finding's brief never lingers.
  useEffect(() => {
    setAdvisory(null)
    setAdvisoryError(null)
    if (!selectedId) return
    const id = Number(selectedId)
    if (!Number.isFinite(id)) return
    let active = true
    getFindingAdvisory(id)
      .then((a) => { if (active) setAdvisory(a) })
      .catch((e) => {
        if (active) setAdvisoryError(e instanceof Error ? e.message : String(e))
      })
    return () => { active = false }
  }, [selectedId])

  // Deep link: open the drawer for `?finding=<id>` on first mount by fetching
  // its detail directly (the row may not be on the current page/filter). Runs
  // once for the initial id; the detail read above then keeps it fresh.
  useEffect(() => {
    if (!initialFindingId) return
    const id = Number(initialFindingId)
    if (!Number.isFinite(id)) return
    let active = true
    setDeepLinkMissing(false)
    getFindingDetail(id)
      .then((raw) => { if (active) setSelectedFinding(mapApiFinding(raw)) })
      .catch(() => {
        // Missing and out-of-scope findings are indistinguishable (both 404),
        // so one message covers both without leaking whether the id exists.
        // Keep the list in view rather than dead-ending on a full-page 404.
        if (active) setDeepLinkMissing(true)
      })
    return () => { active = false }
  }, [initialFindingId])

  // Mirror the active filters + open drawer into the URL so the view is
  // shareable, bookmarkable, and survives a refresh. Opt-in (`syncUrl`) — only
  // the standalone /findings route enables it; embedded uses share their host
  // page's URL. Uses replaceState, not router navigation: the list already
  // refetches on filter changes, so we only reflect state into the address bar
  // without a server round-trip or a stack of history entries. `page` and
  // collapsed-group state are deliberately omitted — they are view ephemera,
  // not filters, and page resets on any filter change.
  useEffect(() => {
    if (!syncUrl || typeof window === "undefined") return
    const params = new URLSearchParams()
    for (const key of URL_SYNC_KEYS) {
      const value = currentUrlState[key]
      if (value) params.set(key, value)
    }
    if (selectedId != null) params.set("finding", String(selectedId))
    const qs = params.toString()
    window.history.replaceState(null, "", qs ? `${window.location.pathname}?${qs}` : window.location.pathname)
  }, [syncUrl, currentUrlState, selectedId])

  useEffect(() => setDismissError(null), [selectedFinding])

  // Auto-expire the undo affordance after a few seconds.
  useEffect(() => {
    if (!lastDismissed) return
    const t = window.setTimeout(() => setLastDismissed(null), 7000)
    return () => window.clearTimeout(t)
  }, [lastDismissed])

  // Auto-expire the missing-deep-link notice.
  useEffect(() => {
    if (!deepLinkMissing) return
    const t = window.setTimeout(() => setDeepLinkMissing(false), 6000)
    return () => window.clearTimeout(t)
  }, [deepLinkMissing])

  // Drop one id from the multi-select set — used when a row leaves the list via
  // dismiss/defer/reopen so the bulk bar count stays truthful.
  const deselect = useCallback((id: string) => {
    setSelection((prev) => {
      if (!prev.has(id)) return prev
      const next = new Set(prev)
      next.delete(id)
      return next
    })
  }, [])

  const handleDismissCurrent = useCallback(async (reason: DismissReason) => {
    const current = selectedFinding
    if (!current || dismissing) return
    const id = Number(current.id)
    if (!Number.isFinite(id)) {
      setDismissError("This finding can't be dismissed here.")
      return
    }
    setDismissing(true)
    setDismissError(null)
    try {
      await bulkDismissFindings([id], reason)
      const idx = sorted.findIndex((f) => f.id === current.id)
      const next = sorted[idx + 1] ?? sorted[idx - 1] ?? null
      setFindings((rows) => rows.filter((r) => r.id !== current.id))
      setTotalCount((c) => Math.max(0, c - 1))
      setScannerTotals((prev) => ({ ...prev, [current.scanner]: Math.max(0, (prev[current.scanner] ?? 1) - 1) }))
      deselect(current.id)
      setLastDismissed({ finding: current, index: Math.max(0, idx), verb: "Dismissed" })
      setSelectedFinding(next && next.id !== current.id ? next : null)
    } catch (e) {
      setDismissError(e instanceof Error ? e.message : "Dismiss failed")
    } finally {
      setDismissing(false)
    }
  }, [selectedFinding, sorted, dismissing, deselect])

  // Defer (snooze) the open finding — same drop-and-advance flow as dismiss; the
  // undo toast reopens it (reopen handles deferred too).
  const handleDeferCurrent = useCallback(async () => {
    const current = selectedFinding
    if (!current || deferring) return
    const id = Number(current.id)
    if (!Number.isFinite(id)) {
      setDismissError("This finding can't be deferred here.")
      return
    }
    setDeferring(true)
    setDismissError(null)
    try {
      await deferFinding(id)
      const idx = sorted.findIndex((f) => f.id === current.id)
      const next = sorted[idx + 1] ?? sorted[idx - 1] ?? null
      setFindings((rows) => rows.filter((r) => r.id !== current.id))
      setTotalCount((c) => Math.max(0, c - 1))
      setScannerTotals((prev) => ({ ...prev, [current.scanner]: Math.max(0, (prev[current.scanner] ?? 1) - 1) }))
      deselect(current.id)
      setLastDismissed({ finding: current, index: Math.max(0, idx), verb: "Deferred" })
      setSelectedFinding(next && next.id !== current.id ? next : null)
    } catch (e) {
      setDismissError(e instanceof Error ? e.message : "Defer failed")
    } finally {
      setDeferring(false)
    }
  }, [selectedFinding, sorted, deferring, deselect])

  const handleReopenCurrent = useCallback(async () => {
    const current = selectedFinding
    if (!current || reopening) return
    const id = Number(current.id)
    if (!Number.isFinite(id)) {
      setDismissError("This finding can't be reopened here.")
      return
    }
    setReopening(true)
    setDismissError(null)
    try {
      await reopenFinding(id)
      if (stateFilter === "all") {
        // The "all" view keeps the finding — flip its state in place so the
        // banner drops and the action row returns to Defer/Dismiss.
        setSelectedFinding((curr) =>
          curr && curr.id === current.id ? { ...curr, state: "open" } : curr,
        )
        setFindings((rows) =>
          rows.map((r) => (r.id === current.id ? { ...r, state: "open" } : r)),
        )
      } else {
        // A state-scoped view (dismissed/deferred/fixed/closed) no longer
        // matches a reopened finding — drop and advance, mirroring dismiss and
        // defer. No undo toast: the undo path re-opens, so it can't faithfully
        // restore the prior closed sub-state.
        const idx = sorted.findIndex((f) => f.id === current.id)
        const next = sorted[idx + 1] ?? sorted[idx - 1] ?? null
        setFindings((rows) => rows.filter((r) => r.id !== current.id))
        setTotalCount((c) => Math.max(0, c - 1))
        setScannerTotals((prev) => ({ ...prev, [current.scanner]: Math.max(0, (prev[current.scanner] ?? 1) - 1) }))
        deselect(current.id)
        setSelectedFinding(next && next.id !== current.id ? next : null)
      }
    } catch (e) {
      setDismissError(e instanceof Error ? e.message : "Reopen failed")
    } finally {
      setReopening(false)
    }
  }, [selectedFinding, reopening, stateFilter, sorted, deselect])

  const handleUndoDismiss = useCallback(async () => {
    const d = lastDismissed
    if (!d) return
    setLastDismissed(null)
    // Optimistically restore the row at its original position and re-open it.
    setFindings((rows) => {
      if (rows.some((r) => r.id === d.finding.id)) return rows
      const copy = rows.slice()
      copy.splice(Math.min(d.index, copy.length), 0, d.finding)
      return copy
    })
    setTotalCount((c) => c + 1)
    // Restore the scanner's total too, mirroring the dismiss/defer decrement, so
    // the per-group paginator's page count stays correct after an undo.
    setScannerTotals((prev) => ({ ...prev, [d.finding.scanner]: (prev[d.finding.scanner] ?? 0) + 1 }))
    setSelectedFinding(d.finding)
    try {
      await reopenFinding(Number(d.finding.id))
    } catch {
      setDismissError("Couldn't undo — the finding may remain actioned.")
    }
  }, [lastDismissed])

  useEffect(() => {
    if (!selectedFinding) return
    function onNavKey(e: KeyboardEvent) {
      // Don't navigate the queue underneath a nested sheet (e.g. the code
      // Expand view), and don't steal arrows from form controls or menus.
      if (openSheetCount() > 1) return
      const el = e.target as HTMLElement | null
      const tag = el?.tagName
      const role = el?.getAttribute?.("role")
      if (
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        el?.isContentEditable ||
        role === "menu" ||
        role === "menuitem" ||
        role === "combobox" ||
        role === "listbox"
      ) {
        return
      }
      if (e.key === "j" || e.key === "ArrowDown") {
        e.preventDefault()
        goToAdjacent(1)
      } else if (e.key === "k" || e.key === "ArrowUp") {
        e.preventDefault()
        goToAdjacent(-1)
      }
    }
    window.addEventListener("keydown", onNavKey)
    return () => window.removeEventListener("keydown", onNavKey)
  }, [selectedFinding, goToAdjacent])

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
    // Flat queue mode (/inbox) skips the group-by axis entirely and renders
    // every row in a single unlabelled bucket.
    if (flat) {
      return [{ key: "all" as const, label: "", rows: sorted }]
    }
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
  }, [sorted, groupBy, flat])

  const showEmpty = !loading && !error && sorted.length === 0
  // Keep the table visible while a refetch is in flight (only the first load,
  // with nothing yet to show, falls back to the skeleton). Otherwise paging one
  // scanner group — which refetches every group — would blank the whole list.
  const showTable = !error && sorted.length > 0

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
    moreFilters.bands.length === 0 &&
    moreFilters.assigneeUserId === null
  const showGhostPreview =
    showEmpty && hasNoFilters && totalCount === 0

  return (
    <div className="flex h-full flex-col overflow-hidden bg-[var(--color-bg)]">
      <IntelLiveBanner message={intelMessage} onDismiss={handleIntelDismiss} />

      {!hideHeader && (
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
      )}

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
            repo={repoFilter}
            state={stateFilter}
            scanner={scannerFilter}
            moreFilters={moreFilters}
            onSeverityChange={(next) => setSevFilter(next as Severity | "all")}
            onRepoChange={setRepoFilter}
            onStateChange={(next) => setStateFilter(next as StateFilter)}
            onScannerChange={(next) => setScannerFilter(next as ScannerFilter)}
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

        <div className="border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-2.5 space-y-3">
          <EnableVerificationBanner verificationEnabled={verificationEnabled} />
          <VerdictFilterChips
            active={verdictFilter}
            counts={verdictCounts}
            onChange={setVerdictFilter}
          />
        </div>

        {loading && sorted.length === 0 && (
          <div className="divide-y divide-[var(--color-border-divider)]" aria-hidden="true">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-3">
                <span className="h-2 w-2 shrink-0 rounded-full bg-[var(--color-surface-raised)] motion-safe:animate-pulse" />
                <Skeleton className="h-3 w-[40%]" />
                <Skeleton className="ml-auto h-3 w-12 hidden md:block" />
                <Skeleton className="h-3 w-24 hidden lg:block" />
                <Skeleton className="h-3 w-10" />
              </div>
            ))}
          </div>
        )}

        {error && (
          <div className="flex items-center justify-between border-b border-[var(--color-border-divider)] px-5 py-3 text-xs text-[var(--color-severity-high-text)]">
            <span>{error}</span>
            <Button variant="secondary" size="xs" onClick={handleRetry}>
              Retry
            </Button>
          </div>
        )}

        {showGhostPreview ? (
          <div className="space-y-4 px-5 py-4">
            {hasSourceConnections !== null && (
              <EmptyOverviewBanner
                {...(hasSourceConnections === true && {
                  title: "No findings yet",
                  description: "Your source is connected. Run a scan to start seeing findings here.",
                  ctaHref: "/sources",
                  ctaLabel: "View sources",
                })}
              />
            )}
            <GhostPreviewWrapper>
              <FindingsGhostPreview flat={flat} />
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
                  void load(sevFilter, scannerFilter, searchQuery, repoFilter, stateFilter, sortKey, agePreset, verdictFilter, page)
                  clearSelection()
                }}
              />
            )}
            <div className="divide-y divide-[var(--color-border)]">
              {groups.map((group) => (
                <div key={`${groupBy}:${group.key}`}>
                  {!flat && (
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
                  )}
                  {!collapsedGroups.has(group.key) && (() => {
                    // Per-scanner mode: the page is already capped at PAGE_SIZE,
                    // so render every row and give the group its own paginator.
                    if (perScannerMode) {
                      return (
                        <>
                          {group.rows.map((finding) => (
                            <CompactFindingRow
                              key={finding.id}
                              finding={finding}
                              selected={selection.has(finding.id)}
                              onToggleSelect={() => toggleSelect(finding.id)}
                              onOpen={() => setSelectedFinding(finding)}
                              active={selectedFinding?.id === finding.id}
                            />
                          ))}
                          <FindingsPagination
                            page={scannerPages[group.key] ?? 1}
                            pageSize={PAGE_SIZE}
                            total={scannerTotals[group.key] ?? 0}
                            onChange={(p) => setScannerPages((prev) => ({ ...prev, [group.key]: p }))}
                          />
                        </>
                      )
                    }
                    // Flat queue mode renders every row — no progressive
                    // disclosure since there's only one bucket.
                    const expanded = flat || expandedGroups.has(group.key)
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
                        {!flat && !expanded && hiddenCount > 0 && (
                          <Button
                            variant="link"
                            className="w-full justify-center px-4 py-2 text-xs text-[var(--color-text-secondary)]"
                            onClick={() =>
                              setExpandedGroups((prev) => {
                                const next = new Set(prev); next.add(group.key); return next
                              })
                            }
                            aria-label={`Show ${hiddenCount} more findings in ${group.label}`}
                          >
                            {`Show ${group.rows.length - INITIAL_ROWS_PER_GROUP} more ${group.label.toLowerCase()} →`}
                          </Button>
                        )}
                      </>
                    )
                  })()}
                </div>
              ))}
            </div>

            {!perScannerMode && (
              <FindingsPagination
                page={page}
                pageSize={PAGE_SIZE}
                total={totalCount}
                onChange={setPage}
              />
            )}
          </>
        )}

        {showTable && !compactHeader && (
          <>
            {/* table-fixed so columns share the page width: the Finding column
                flexes into the remaining space while the rest stay fixed,
                instead of the table overflowing and clipping later columns. */}
            <Table className="border-collapse table-fixed w-full">
              <Thead className="sticky top-0 z-10 bg-[var(--color-surface)]">
                <Tr>
                  <Th className="w-[5.5rem] px-4 py-2.5">Severity</Th>
                  <Th className="px-3 py-2.5">Finding</Th>
                  <Th className="w-[14rem] px-3 py-2.5 hidden md:table-cell">Scanner</Th>
                  <Th className="w-[12rem] px-3 py-2.5 hidden lg:table-cell">Repository</Th>
                  <SortableTh
                    label="Exploitability"
                    className="w-[8rem] px-3 py-2.5 text-right [&>button]:justify-end [&>button]:w-full"
                    direction={sortKey === "action_band" ? "descending" : "none"}
                    onClick={() => setSortKey("action_band")}
                  />
                  <SortableTh
                    label="CVSS"
                    className="w-[5rem] px-3 py-2.5 text-right hidden sm:table-cell [&>button]:justify-end [&>button]:w-full"
                    direction={sortKey === "cvss" ? "descending" : "none"}
                    onClick={() => setSortKey("cvss")}
                  />
                  <Th className="w-[7rem] px-3 py-2.5 text-right hidden sm:table-cell">Confidence</Th>
                  <SortableTh
                    label="Age"
                    className="w-[4.5rem] px-3 py-2.5 text-right hidden sm:table-cell [&>button]:justify-end [&>button]:w-full"
                    direction={
                      sortKey === "oldest"
                        ? "descending"
                        : sortKey === "newest"
                          ? "ascending"
                          : "none"
                    }
                    onClick={() => setSortKey(sortKey === "newest" ? "oldest" : "newest")}
                  />
                </Tr>
              </Thead>
              {groups.map((group) => (
                <Tbody key={`${groupBy}:${group.key}`}>
                  <Tr className="bg-[var(--color-bg-section)]">
                    <Td colSpan={8} className="px-0 py-0">
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
                    </Td>
                  </Tr>
                  {!collapsedGroups.has(group.key) && (() => {
                    // Per-scanner mode renders the whole page-capped group and
                    // swaps the "Show N more" reveal for the group's own paginator.
                    const expanded = perScannerMode || expandedGroups.has(group.key)
                    const visible = expanded ? group.rows : group.rows.slice(0, INITIAL_ROWS_PER_GROUP)
                    const hiddenCount = group.rows.length - INITIAL_ROWS_PER_GROUP
                    return (
                      <>
                        {visible.map((finding) => (
                          <Tr
                            key={finding.id}
                            interactive
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
                            className={`cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset ${
                              selectedFinding?.id === finding.id ? "bg-[var(--color-nav-active)]" : ""
                            }`}
                          >
                            <Td className="px-4 py-3">
                              <span
                                className="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-2xs font-bold uppercase tracking-wide"
                                style={{
                                  color: SEV_COLOR[finding.severity],
                                  background: `color-mix(in srgb, ${SEV_COLOR[finding.severity]} 14%, transparent)`,
                                }}
                              >
                                <span
                                  className="h-1.5 w-1.5 rounded-full"
                                  style={{ background: SEV_COLOR[finding.severity] }}
                                  aria-hidden="true"
                                />
                                {SEVERITY_GROUP_LABEL[finding.severity]}
                              </span>
                            </Td>

                            <Td className="px-3 py-3">
                              <div className="min-w-0">
                                <div className="flex items-center gap-2 min-w-0">
                                  <span className="font-medium text-[var(--color-text-primary)] truncate">
                                    {finding.title}
                                  </span>
                                  <FindingRowTags
                                    malicious={finding.malicious}
                                    kev={finding.kev}
                                    epssPercentile={finding.epssPercentile}
                                    firstSeen={finding.firstSeen}
                                  />
                                  {finding.cve && (
                                    <span className="shrink-0 font-[family-name:var(--font-jetbrains-mono)] text-[11.5px] text-[var(--color-text-tertiary)]">
                                      {finding.cve}
                                    </span>
                                  )}
                                </div>
                                {finding.verdict === "ruled_out" && finding.ruledOutReason && (
                                  <p
                                    className="mt-0.5 flex items-baseline gap-1.5 text-2xs text-[var(--color-text-tertiary)]"
                                    title={finding.ruledOutReason}
                                  >
                                    <span className="shrink-0 font-semibold uppercase tracking-[0.14em] text-[var(--color-status-ok-text)]">
                                      Ruled out
                                    </span>
                                    <span className="truncate">{finding.ruledOutReason}</span>
                                  </p>
                                )}
                              </div>
                            </Td>

                            <Td className="px-3 py-3 hidden md:table-cell">
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
                            </Td>

                            <Td className="px-3 py-3 hidden lg:table-cell">
                              <span className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-secondary)] truncate max-w-[16rem]">
                                {finding.repo}
                              </span>
                            </Td>

                            <Td className="px-3 py-3 text-right">
                              {finding.actionBand ? (
                                <span className="inline-flex justify-end">
                                  <ActionBandBadge band={finding.actionBand} />
                                </span>
                              ) : (
                                <span className="text-[var(--color-text-tertiary)] text-xs text-right block">—</span>
                              )}
                            </Td>

                            <Td className="px-3 py-3 text-right hidden sm:table-cell">
                              {typeof finding.cvssScore === "number" ? (
                                <span className="text-xs font-semibold tabular-nums text-[var(--color-text-primary)]">
                                  {finding.cvssScore.toFixed(1)}
                                </span>
                              ) : (
                                <span className="text-[var(--color-text-tertiary)] text-xs">—</span>
                              )}
                            </Td>

                            <Td className="px-3 py-3 text-right hidden sm:table-cell">
                              {finding.verdict ? (
                                <span className="inline-flex justify-end">
                                  <VerdictBadge verdict={finding.verdict} />
                                </span>
                              ) : (
                                <span className="text-2xs text-[var(--color-text-tertiary)]">Unrated</span>
                              )}
                            </Td>

                            <Td className="px-3 py-3 text-right hidden sm:table-cell">
                              <FindingAge age={finding.age} className="text-xs text-[var(--color-text-tertiary)]" />
                            </Td>
                          </Tr>
                        ))}
                        {perScannerMode ? (
                          <Tr>
                            <Td colSpan={8} className="p-0">
                              <FindingsPagination
                                page={scannerPages[group.key] ?? 1}
                                pageSize={PAGE_SIZE}
                                total={scannerTotals[group.key] ?? 0}
                                onChange={(p) => setScannerPages((prev) => ({ ...prev, [group.key]: p }))}
                              />
                            </Td>
                          </Tr>
                        ) : !expanded && hiddenCount > 0 ? (
                          <Tr>
                            <Td colSpan={8} className="p-0">
                              <Button
                                variant="link"
                                className="w-full justify-center py-2 text-xs text-[var(--color-text-secondary)]"
                                onClick={() =>
                                  setExpandedGroups((prev) => {
                                    const next = new Set(prev); next.add(group.key); return next
                                  })
                                }
                                aria-label={`Show ${hiddenCount} more findings in ${group.label}`}
                              >
                                {`Show ${group.rows.length - INITIAL_ROWS_PER_GROUP} more ${group.label.toLowerCase()} →`}
                              </Button>
                            </Td>
                          </Tr>
                        ) : null}
                      </>
                    )
                  })()}
                </Tbody>
              ))}
            </Table>

            {!perScannerMode && (
              <FindingsPagination
                page={page}
                pageSize={PAGE_SIZE}
                total={totalCount}
                onChange={setPage}
              />
            )}
          </>
        )}
        </div>
        </div>

        <Sheet
          open={!!selectedFinding}
          onClose={() => setSelectedFinding(null)}
          size="lg"
          title={selectedFinding?.title ?? "Finding"}
          header={
            selectedFinding ? (
              <DrawerHeader
                eyebrow={`${selectedFinding.severity.charAt(0).toUpperCase()}${selectedFinding.severity.slice(1)} · ${SCANNER_GROUP_LABEL[selectedFinding.scanner]}`}
                eyebrowDotColor={SEV_COLOR[selectedFinding.severity]}
                title={selectedFinding.title}
                identifier={selectedFinding.cve ?? selectedFinding.filePath}
                badges={<FindingDetailBadges finding={selectedFinding} />}
                onClose={() => setSelectedFinding(null)}
                onPrev={() => goToAdjacent(-1)}
                onNext={() => goToAdjacent(1)}
                hasPrev={hasPrevFinding}
                hasNext={hasNextFinding}
                position={globalPos >= 0 ? globalPos + 1 : undefined}
                total={queueTotal}
              />
            ) : (
              <span />
            )
          }
        >
          {selectedFinding && (
            <>
              {selectedFinding.state && selectedFinding.state !== "open" && (
                <DrawerStatusBanner state={selectedFinding.state} />
              )}
              <FindingDetailActions
                assigneeControl={
                  <div className="w-44">
                    <FindingAssigneeEditor
                      size="sm"
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
                  </div>
                }
                {...(selectedFinding.state && selectedFinding.state !== "open"
                  ? { onReopen: handleReopenCurrent, reopenBusy: reopening }
                  : {
                      onDefer: handleDeferCurrent,
                      canDefer: !deferring,
                      dismiss: {
                        reasons: DISMISS_REASONS,
                        onDismiss: (reason: string) =>
                          handleDismissCurrent(reason as DismissReason),
                        busy: dismissing,
                        error: dismissError,
                      },
                    })}
              />

              <div className="flex-1 overflow-y-auto pb-10 divide-y divide-[var(--color-border-divider)]">
              {detailError && (
                <div
                  role="alert"
                  className="border-l-2 border-[var(--color-severity-critical)] bg-[color-mix(in_srgb,var(--color-severity-critical)_8%,transparent)] px-5 py-4 text-sm text-[var(--color-severity-critical-text)]"
                >
                  <p className="font-semibold">Couldn&apos;t load the full detail for this finding.</p>
                  <p className="mt-1 break-words text-[var(--color-text-secondary)]">
                    Showing the summary only — code, verification, and remediation may be missing.
                  </p>
                  <p className="mt-1 break-words font-mono text-2xs text-[var(--color-text-tertiary)]">{detailError}</p>
                </div>
              )}
              <FindingDrawerGroup id="overview" label="Overview">
              <TriageBanner finding={selectedFinding} />

              <FindingDescriptionSection
                description={selectedFinding.description}
                title={selectedFinding.title}
                emphasized={selectedFinding.scanner === "agent_scanning"}
              />

              <FindingSignalRow finding={selectedFinding} />

              <AdvisoryHeader finding={selectedFinding} />
              </FindingDrawerGroup>

              <FindingDrawerGroup id="analysis" label="Analysis">
              <SummarySection
                chain={selectedFinding.exploitChain ?? undefined}
                refCount={selectedFinding.evidence?.length ?? 0}
              />

              <TechnicalDetailSection evidence={selectedFinding.evidence} />

              {selectedFinding.scanner === "secret_scanning" && (
                <SecretVerificationSection
                  verified={selectedFinding.secretVerified}
                  detector={selectedFinding.secretDetector}
                />
              )}

              <CodePreviewSection
                snippet={selectedFinding.codeSnippet}
                filePath={selectedFinding.filePath}
                startLine={selectedFinding.codeSnippetStartLine}
                highlightStart={selectedFinding.highlightStart}
                highlightEnd={selectedFinding.highlightEnd}
                secretFindingId={
                  selectedFinding.scanner === "secret_scanning"
                    ? selectedFinding.id
                    : undefined
                }
                showEmptyWhenMissing={selectedFinding.scanner !== "secret_scanning"}
                detailLoading={detailLoading}
                scanner={selectedFinding.scanner}
                repoUrl={buildRepoFileUrl({
                  repo: selectedFinding.repo,
                  filePath: selectedFinding.filePath,
                  commit: selectedFinding.introducedByCommit,
                  repoHtmlUrl: selectedFinding.repoHtmlUrl,
                })}
              />

              {selectedFinding.codeFlows && selectedFinding.codeFlows.length > 0 ? (
                <FindingDataFlowSection steps={selectedFinding.codeFlows} />
              ) : (
                <section className="space-y-2">
                  <h3 className="text-base font-semibold text-[var(--color-text-primary)]">Call path (verified)</h3>
                  <p className="text-sm leading-relaxed text-[var(--color-text-tertiary)]">
                    No verified call path — verify this finding to trace source → sink.
                  </p>
                </section>
              )}

              <AttackScenarioSection
                reproduction={selectedFinding.verificationMetadata?.reproduction}
                attackPaths={selectedFinding.verificationMetadata?.attack_paths}
                refCount={selectedFinding.evidence?.length ?? 0}
              />

              <ImpactSection impact={selectedFinding.verificationMetadata?.impact} />

              <DistinctnessSection distinctness={selectedFinding.verificationMetadata?.distinctness} />

              <FindingPocSection
                findingId={Number(selectedFinding.id)}
                pocScript={selectedFinding.verificationMetadata?.poc_script}
                pocFilename={selectedFinding.verificationMetadata?.poc_filename}
                pocLanguage={selectedFinding.verificationMetadata?.poc_language}
                onGenerated={handlePocGenerated}
              />

              <NotesVerificationSection
                verdict={selectedFinding.verdict}
                metadata={selectedFinding.verificationMetadata}
              />

              <FindingAcceptRiskAction finding={selectedFinding} />
              </FindingDrawerGroup>

              <FindingDrawerGroup id="remediation" label="Remediation">
              <RecommendedFixSection fix={selectedFinding.recommendedFix} />
              {selectedFinding.recommendedFix && selectedFinding.verificationMetadata?.fix_verified && (
                <p className="mt-2 inline-flex items-center gap-1.5 rounded-md bg-[var(--color-state-fixed-subtle)] px-2 py-1 text-2xs font-medium text-[var(--color-state-fixed-text)]">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="h-3 w-3">
                    <path d="M20 6 9 17l-5-5" />
                  </svg>
                  Fix verified — applies cleanly to the current code
                </p>
              )}

              {/* Fall back to the scanner's own remediation text only when there
                  is no structured fix, so the "Recommended fix" heading never
                  renders twice. */}
              {!selectedFinding.recommendedFix && (
                <FindingRemediationSection remediation={selectedFinding.remediation} />
              )}
              </FindingDrawerGroup>

              <FindingDrawerGroup id="context" label="Context" defaultOpen={false}>
              <CweContextSection cwe={selectedFinding.cwe} />

              <SecurityBriefSection advisory={advisory} />

              {advisoryError && (
                <div role="alert" className="text-sm">
                  <p className="font-semibold text-[var(--color-severity-high-text)]">
                    Couldn&apos;t load the advisory brief.
                  </p>
                  <p className="mt-1 break-words font-mono text-2xs text-[var(--color-text-tertiary)]">{advisoryError}</p>
                </div>
              )}

              <BlastRadiusSection
                findingId={Number(selectedFinding.id)}
                count={selectedFinding.alsoAffectsRepos}
              />

              <ContainerImageSection image={selectedFinding.containerImage} />

              <FindingOriginSection
                finding={selectedFinding}
                scannerLabel={SCANNER_LABEL[selectedFinding.scanner]}
              />

              {/* Reference metadata: rule, weakness id, package, repository. */}
              <section aria-labelledby="finding-details-title">
                <h3 id="finding-details-title" className="text-base font-semibold text-[var(--color-text-primary)]">
                  Details
                </h3>
                <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
                  {selectedFinding.rule && (
                    <div className="col-span-2 min-w-0">
                      <dt className="text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Rule</dt>
                      <dd
                        className="mt-1 truncate font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-primary)]"
                        title={selectedFinding.rule}
                      >
                        {selectedFinding.rule}
                      </dd>
                    </div>
                  )}
                  {selectedFinding.cwe && (
                    <div>
                      <dt className="text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">CWE</dt>
                      <dd className="mt-1 text-sm text-[var(--color-text-primary)]">
                        <CweValue cwe={selectedFinding.cwe} />
                      </dd>
                    </div>
                  )}
                  {selectedFinding.package && (
                    <div className="col-span-2 min-w-0">
                      <dt className="text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Package</dt>
                      <dd
                        className="mt-1 truncate font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-primary)]"
                        title={selectedFinding.package}
                      >
                        {selectedFinding.package}
                      </dd>
                    </div>
                  )}
                  {selectedFinding.secretDetector && (
                    <div>
                      <dt className="text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Detector</dt>
                      <dd className="mt-1 text-sm text-[var(--color-text-primary)]">
                        {selectedFinding.secretDetector}
                      </dd>
                    </div>
                  )}
                  <div className="min-w-0">
                    <dt className="text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">Repository</dt>
                    <dd
                      className="mt-1 truncate font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-primary)]"
                      title={selectedFinding.repo}
                    >
                      {selectedFinding.repo}
                    </dd>
                  </div>
                </dl>
              </section>

              <FindingReferencesSection
                cve={selectedFinding.cve}
                cwe={selectedFinding.cwe}
                advisoryReferences={advisory?.references}
              />
              </FindingDrawerGroup>

              <FindingDrawerGroup id="activity" label="Activity" defaultOpen={false}>
              <ActivityTimelineSection key={selectedFinding.id} finding={selectedFinding} scannerLabel={SCANNER_LABEL[selectedFinding.scanner]} />
              </FindingDrawerGroup>

              <div className="px-5 py-4">
                <section className="space-y-2">
                  <h3 className="text-base font-semibold text-[var(--color-text-primary)]">Testing &amp; Safe Harbor</h3>
                  <p className="text-xs text-[var(--color-text-secondary)]">
                    Findings are verified locally against source with benign proof-of-concept payloads;
                    no production systems or user data are accessed. Reports are confidential pending a fix.
                  </p>
                </section>
              </div>
              </div>
            </>
          )}
        </Sheet>
      </div>

      {lastDismissed && (
        <div
          role="status"
          aria-live="polite"
          className="fixed bottom-6 left-1/2 z-[110] flex -translate-x-1/2 items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-2.5 shadow-xl"
        >
          <span className="text-sm text-[var(--color-text-primary)]">
            {lastDismissed.verb}{" "}
            <span className="inline-block max-w-[14rem] truncate align-bottom font-medium" title={lastDismissed.finding.title}>
              {lastDismissed.finding.title}
            </span>
          </span>
          <Button
            variant="link"
            size="sm"
            onClick={handleUndoDismiss}
            className="font-semibold text-[var(--color-accent)] hover:underline"
          >
            Undo
          </Button>
        </div>
      )}

      {deepLinkMissing && (
        <div
          role="status"
          aria-live="polite"
          className="fixed bottom-6 left-1/2 z-[110] flex -translate-x-1/2 items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4 py-2.5 shadow-xl"
        >
          <span className="text-sm text-[var(--color-text-primary)]">
            That finding no longer exists or isn’t in your scope.
          </span>
          <Button
            variant="ghost"
            size="xs"
            onClick={() => setDeepLinkMissing(false)}
            className="font-semibold"
          >
            Dismiss
          </Button>
        </div>
      )}
    </div>
  )
}

const NEUTRAL = "text-[var(--color-text-primary)]"
const CRITICAL = "text-[var(--color-severity-critical-text)]"
const WARN = "text-[var(--color-severity-high-text)]"
const OK = "text-[var(--color-state-fixed-text)]"

// The scanner's plain-language explanation of the issue — the first thing an
// analyst needs to decide whether the finding is real. Hidden when it would
// just repeat the title.
function FindingDescriptionSection({
  description,
  title,
  emphasized = false,
}: {
  description?: string
  title: string
  // Scanners without an LLM verifier (e.g. agent) carry a curated advisory that
  // is itself an impact statement; render it with the same weight the verifier's
  // Impact line gets rather than as a plain paragraph.
  emphasized?: boolean
}) {
  // The title is often the first sentence of the description. Drop that lead so
  // "What's wrong" adds context instead of repeating the headline; hide entirely
  // when nothing remains.
  const t = title.trim()
  const desc = (description ?? "").trim()
  const body = desc === t ? "" : desc.startsWith(t) ? desc.slice(t.length).trim() : desc
  if (!body) return null
  if (emphasized) {
    return (
      <section aria-labelledby="finding-description-title">
        <h3 id="finding-description-title" className="sr-only">
          Impact
        </h3>
        <ImpactCallout>{body}</ImpactCallout>
      </section>
    )
  }
  return (
    <section aria-labelledby="finding-description-title">
      <h3 id="finding-description-title" className="text-base font-semibold text-[var(--color-text-primary)]">
        What&rsquo;s wrong
      </h3>
      <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-[var(--color-text-secondary)]">
        {body}
      </p>
    </section>
  )
}

function FindingRemediationSection({ remediation }: { remediation?: string }) {
  // ponytail: a `$FUNC`-style token means the scanner handed us its raw rule
  // template, not a usable fix — show the empty state instead of echoing it.
  // Ceiling: also suppresses a real fix literally containing `$UPPER`; scanner
  // remediation text rarely does, so fine until it bites.
  const usable = remediation ? !/\$[A-Z][A-Z0-9_]*/.test(remediation) : false
  return (
    <section aria-labelledby="finding-remediation-title">
      <h3 id="finding-remediation-title" className="text-base font-semibold text-[var(--color-text-primary)]">
        Recommended fix
      </h3>
      {usable ? (
        <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-[var(--color-text-primary)]">
          {remediation}
        </p>
      ) : (
        <p className="mt-2 text-sm leading-relaxed text-[var(--color-text-tertiary)]">
          No automated fix yet — verify this finding to generate one.
        </p>
      )}
    </section>
  )
}

// Consolidated "how bad / how exploitable" strip — the at-a-glance signals a
// triager weighs before reading detail: risk, known-exploited, EPSS, scanner
// confidence, and the AI verdict. Each chip renders only when its signal is
// present, so the row adapts to what the scanner supplied.
function SignalChip({
  tone,
  title,
  children,
}: {
  tone: "danger" | "warn" | "success" | "neutral"
  title?: string
  children: ReactNode
}) {
  const tones: Record<typeof tone, string> = {
    danger:
      "border-[color-mix(in_srgb,var(--color-severity-critical)_45%,transparent)] bg-[color-mix(in_srgb,var(--color-severity-critical)_12%,transparent)] text-[var(--color-severity-critical-text)]",
    warn:
      "border-[color-mix(in_srgb,var(--color-severity-high)_40%,transparent)] bg-[color-mix(in_srgb,var(--color-severity-high)_12%,transparent)] text-[var(--color-severity-high-text)]",
    success:
      "border-[color-mix(in_srgb,var(--color-status-ok)_40%,transparent)] bg-[color-mix(in_srgb,var(--color-status-ok)_12%,transparent)] text-[var(--color-status-ok-text)]",
    neutral:
      "border-[var(--color-border)] bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]",
  }
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium",
        tones[tone],
      )}
    >
      {children}
    </span>
  )
}

// One-line triage headline at the top of the drawer — the verdict + urgency +
// severity thesis an analyst reads before scrolling into the detail below.
function TriageBanner({ finding }: { finding: Finding }) {
  const summary = triageSummary({
    verdict: finding.verdict,
    actionBand: finding.actionBand,
    severity: finding.severity,
    kev: finding.kev,
  })
  if (!summary) return null

  const toneClass =
    summary.tone === "danger"
      ? "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]"
      : summary.tone === "caution"
        ? "border-[var(--color-severity-medium-border)] bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium-text)]"
        : summary.tone === "positive"
          ? "border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok-text)]"
          : "border-[var(--color-border)] bg-[var(--color-bg-section)] text-[var(--color-text-secondary)]"

  return (
    <p
      className={`rounded-md border-l-[3px] px-3 py-2 text-sm font-semibold leading-snug ${toneClass}`}
    >
      {summary.text}
    </p>
  )
}

const SEVERITY_TONE: Record<Finding["severity"], "danger" | "warn" | "neutral"> = {
  critical: "danger",
  high: "warn",
  medium: "neutral",
  low: "neutral",
}

function FindingSignalRow({ finding }: { finding: Finding }) {
  const epssPct = finding.epssPercentile != null ? Math.round(finding.epssPercentile * 100) : null
  const bandTone: "danger" | "warn" | "neutral" =
    finding.actionBand === "act"
      ? "danger"
      : finding.actionBand === "attend"
        ? "warn"
        : "neutral"

  const reach = REACHABILITY_SIGNAL[finding.reachability ?? ""]
  // MITRE exploit-likelihood for the weakness class — the one "how exploitable"
  // read available even when a finding carries no KEV/EPSS/reachability signal.
  const likelihood = cweInfo(finding.cwe)?.likelihood

  // One-line "how severe really" read that narrates the action band via the
  // signals that drove it (KEV / reachability / severity) — turns the chip
  // strip into a plain-language triage call.
  const ctx = severityContext({
    severity: finding.severity,
    actionBand: finding.actionBand,
    kev: finding.kev,
    reachability: finding.reachability,
  })

  // Severity is always present, so the strip always renders with at least the
  // severity read — a finding never collapses to a blank "how bad" band.
  return (
    <div className="space-y-2">
    <div className="flex flex-wrap items-center gap-2" aria-label="Risk signals">
      <SignalChip tone={SEVERITY_TONE[finding.severity]} title="Finding severity">
        <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
        <span className="capitalize">{finding.severity}</span>
      </SignalChip>
      {likelihood && (
        <SignalChip
          tone={likelihood === "High" ? "warn" : "neutral"}
          title="MITRE likelihood of exploit for this weakness class"
        >
          {likelihood} exploit likelihood
        </SignalChip>
      )}
      {finding.actionBand && (
        <SignalChip tone={bandTone} title="SSVC action band — derived from KEV, reachability, and severity">
          <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
          {ACTION_BAND_LABEL[finding.actionBand]}
        </SignalChip>
      )}
      {finding.kev && (
        <SignalChip tone="danger" title="Listed in CISA Known Exploited Vulnerabilities">
          <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="currentColor" aria-hidden="true">
            <path d="M13 2 3 14h7l-1 8 10-12h-7l1-8z" />
          </svg>
          Known exploited
        </SignalChip>
      )}
      {epssPct != null && (
        <SignalChip tone={epssPct >= 50 ? "warn" : "neutral"} title="EPSS exploit-prediction percentile">
          EPSS {epssPct}%
        </SignalChip>
      )}
      {reach && (
        <SignalChip tone={reach.tone} title={reach.title}>
          {reach.glyph}
          {reach.label}
        </SignalChip>
      )}
      {finding.secretVerified != null && (
        <SignalChip
          tone={finding.secretVerified ? "danger" : "neutral"}
          title={
            finding.secretVerified
              ? "The scanner authenticated this credential against the provider — it is live"
              : "The scanner could not confirm this credential is live"
          }
        >
          {finding.secretVerified ? (
            <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="currentColor" aria-hidden="true">
              <path d="M13 2 3 14h7l-1 8 10-12h-7l1-8z" />
            </svg>
          ) : null}
          {finding.secretVerified ? "Live credential" : "Unverified"}
        </SignalChip>
      )}
      {finding.confidence && (
        <SignalChip tone="neutral" title="Scanner confidence">
          <span className="capitalize">{finding.confidence}</span> confidence
        </SignalChip>
      )}
      {finding.verdict && <VerdictBadge verdict={finding.verdict} />}
    </div>
    {ctx && (
      <p
        className={
          ctx.tone === "danger"
            ? "border-l-2 border-[var(--color-severity-critical-border)] pl-3 py-0.5 text-sm leading-relaxed text-[var(--color-text-primary)]"
            : ctx.tone === "caution"
              ? "border-l-2 border-[var(--color-severity-medium-border)] pl-3 py-0.5 text-sm leading-relaxed text-[var(--color-text-primary)]"
              : "border-l-2 border-[var(--color-border)] pl-3 py-0.5 text-sm leading-relaxed text-[var(--color-text-secondary)]"
        }
      >
        {ctx.text}
      </p>
    )}
    </div>
  )
}

// CWE id linked to its MITRE definition so an analyst can read the weakness
// class in one click; renders plain text when the id isn't well-formed.
function CweValue({ cwe }: { cwe: string }) {
  const m = cwe.match(/(?:CWE-)?(\d+)/i)
  if (!m) return <>{cwe}</>
  return (
    <a
      href={`https://cwe.mitre.org/data/definitions/${m[1]}.html`}
      target="_blank"
      rel="noopener noreferrer"
      className="rounded-sm text-[var(--color-accent)] underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
    >
      {cwe}
    </a>
  )
}


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
      return "bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
    case "fixed":
      return "bg-[color-mix(in_srgb,var(--color-state-fixed)_18%,transparent)] text-[var(--color-state-fixed-text)]"
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
  const sevColor = SEV_COLOR[finding.severity]
  const sevLabel = SEVERITY_GROUP_LABEL[finding.severity]
  const isClosed = Boolean(finding.state && finding.state !== "open")

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={`Open ${finding.severity} ${SCANNER_LABEL[finding.scanner]} finding: ${finding.title}`}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault()
          onOpen()
        }
      }}
      className={`relative grid cursor-pointer grid-cols-[18px_minmax(0,1fr)_auto] items-center gap-3 px-4 py-2.5 border-b border-[var(--color-border-divider)] transition-colors hover:bg-[var(--color-surface)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset ${
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

      <div className="min-w-0">
        <div className="flex items-center gap-2 min-w-0">
          {/* Severity as dot + label, not colour alone (a11y: color-not-only). */}
          <span
            className="inline-flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide"
            style={{ color: sevColor, background: `color-mix(in srgb, ${sevColor} 14%, transparent)` }}
          >
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: sevColor }} aria-hidden="true" />
            {sevLabel}
          </span>
          {/* Scanner type — which tool/finding class drives the triage approach. */}
          <span
            className="inline-flex h-[18px] shrink-0 items-center rounded px-1.5 text-[9px] font-bold uppercase tracking-wide"
            style={{ background: SCANNER_BG[finding.scanner], color: SCANNER_FG[finding.scanner] }}
            title={SCANNER_GROUP_LABEL[finding.scanner]}
          >
            {SCANNER_LABEL[finding.scanner]}
          </span>
          <span className="truncate text-[13px] font-medium text-[var(--color-text-primary)]">
            {finding.title}
          </span>
          <FindingRowTags
            malicious={finding.malicious}
            kev={finding.kev}
            epssPercentile={finding.epssPercentile}
            firstSeen={finding.firstSeen}
          />
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-tertiary)]">
          {finding.repo && <span className="truncate">{finding.repo}</span>}
          {finding.filePath && <span className="truncate">{finding.filePath}</span>}
          {finding.cve && <span className="text-[var(--color-text-tertiary)]">{finding.cve}</span>}
        </div>
        {finding.verdict === "ruled_out" && finding.ruledOutReason && (
          <p
            className="mt-0.5 flex items-baseline gap-1.5 text-[11px] text-[var(--color-text-tertiary)]"
            title={finding.ruledOutReason}
          >
            <span className="shrink-0 font-semibold uppercase tracking-[0.1em] text-[var(--color-status-ok-text)]">
              Ruled out
            </span>
            <span className="truncate">{finding.ruledOutReason}</span>
          </p>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-2.5">
        {/* AI verdict is the core triage output; the lifecycle pill only earns
            its place once the finding leaves the default open state. */}
        {isClosed ? (
          <span
            className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider ${statusToneClass(finding.state)}`}
          >
            {statusPillLabel(finding.state)}
          </span>
        ) : finding.verdict ? (
          <VerdictBadge verdict={finding.verdict} />
        ) : null}

        <span className="hidden items-center gap-1.5 sm:flex">
          {finding.actionBand ? (
            <ActionBandBadge band={finding.actionBand} />
          ) : (
            <span className="text-[var(--color-text-tertiary)] text-xs">—</span>
          )}
        </span>

        <FindingAge age={finding.age} className="min-w-[2rem] text-right text-[11px] text-[var(--color-text-tertiary)]" />
      </div>
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
      <Button variant="ghost" size="xs" onClick={onClear} disabled={submitting}>
        Clear
      </Button>
      {error && (
        <span className="text-[12px] text-[var(--color-severity-high-text)]" role="alert">
          {error}
        </span>
      )}
      <div className="ml-auto flex items-center gap-1.5">
        <DismissPopover
          reasons={DISMISS_REASONS}
          onDismiss={(reason) => void handleDismiss(reason as DismissReason)}
          isLoading={submitting}
          triggerLabel={submitting ? "Dismissing…" : "Dismiss with reason"}
          placement="bottom"
        />
      </div>
    </div>
  )
}


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

  const [comments, setComments] = useState<FindingComment[]>([])
  const [commentText, setCommentText] = useState("")
  const [posting, setPosting] = useState(false)
  const [commentError, setCommentError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    const id = Number(finding.id)
    setComments([])
    if (!Number.isFinite(id)) return
    listFindingComments(id)
      .then((rows) => { if (active) setComments(rows) })
      .catch(() => { /* leave empty on failure */ })
    return () => { active = false }
  }, [finding.id])

  async function postComment() {
    const text = commentText.trim()
    const id = Number(finding.id)
    if (!text || !Number.isFinite(id) || posting) return
    setPosting(true)
    setCommentError(null)
    try {
      const created = await addFindingComment(id, text)
      setComments((prev) => [...prev, created])
      setCommentText("")
    } catch (e) {
      setCommentError(e instanceof Error ? e.message : "Couldn't post comment")
    } finally {
      setPosting(false)
    }
  }

  return (
    <section aria-labelledby="finding-activity-title">
      <h3 id="finding-activity-title" className="text-base font-semibold text-[var(--color-text-primary)]">
        Activity
      </h3>

      <ol className="relative mt-3 space-y-3 before:absolute before:left-[11px] before:top-3 before:bottom-3 before:w-px before:bg-[var(--color-border-divider)]">
        {items.map((item, idx) => (
          <li key={idx} className="relative flex gap-3">
            <span className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-full bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]">
              {item.icon}
            </span>
            <div className="min-w-0">
              <div className="text-[13px] text-[var(--color-text-primary)]">{item.body}</div>
              {item.time && <div className="mt-0.5 text-[11px] text-[var(--color-text-tertiary)]">{item.time}</div>}
            </div>
          </li>
        ))}
        {comments.map((c) => (
          <li key={c.id} className="relative flex gap-3">
            <span className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-full bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]">
              <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
              </svg>
            </span>
            <div className="min-w-0">
              <div className="text-[13px] text-[var(--color-text-primary)]">
                <span className="font-medium">{c.actor ?? "Someone"}</span> commented
              </div>
              <div className="mt-0.5 whitespace-pre-wrap text-[13px] text-[var(--color-text-secondary)]">{c.body}</div>
              {c.created_at && (
                <div className="mt-0.5 text-[11px] text-[var(--color-text-tertiary)]">{formatTimelineDate(c.created_at)}</div>
              )}
            </div>
          </li>
        ))}
        {items.length === 0 && comments.length === 0 && (
          <li className="text-[12px] text-[var(--color-text-tertiary)]">No activity yet.</li>
        )}
      </ol>

      <div className="mt-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] p-2">
        <textarea
          value={commentText}
          onChange={(e) => setCommentText(e.target.value)}
          aria-label="Add a comment"
          placeholder="Add a comment…"
          rows={2}
          className="w-full resize-none bg-transparent text-[13px] text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:outline-none"
        />
        {commentError && (
          <p role="alert" className="px-1 text-[11px] text-[var(--color-severity-high-text)]">{commentError}</p>
        )}
        <div className="mt-1 flex justify-end">
          <Button
            variant="secondary"
            size="xs"
            onClick={postComment}
            isLoading={posting}
            disabled={!commentText.trim()}
          >
            Add
          </Button>
        </div>
      </div>
    </section>
  )
}

function FindingDetailBadges({ finding }: { finding: Finding }) {
  // EPSS and risk signals live in the signal strip below; the header badge
  // just carries the finding's age for temporal context.
  const showAge = finding.age && finding.age !== "—"
  if (!showAge) return null
  return (
    <FindingAge
      age={finding.age}
      className="rounded px-2 py-0.5 text-[11px] font-medium text-[var(--color-text-secondary)] bg-[var(--color-surface-raised)]"
    />
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
