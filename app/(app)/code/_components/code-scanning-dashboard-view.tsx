"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import {
  fetchCodeScanningRuns,
  fetchCodeScanningHistory,
  bulkReviewCodeScanningFindings,
  type CodeScanningFinding,
  type CodeScanningScanRun,
} from "@/lib/client/code-scanning-client"
import { useSSE } from "@/components/providers/SSEProvider"
import type { ScanProgressEvent, ScanCompletedEvent, ScanFailedEvent } from "@/lib/shared/sse-types"
import { buildOrgQuery } from "@/lib/shared/org-query"
import { gqlQuery, GraphQLQueryError } from "@/lib/client/graphql-client"
import { CODE_SCANNING_ANALYTICS_QUERY, CODE_SCANNING_FINDINGS_QUERY, CODE_SCANNING_FILTER_OPTIONS_QUERY } from "@/lib/shared/graphql/queries"
import type { GqlCodeScanningAnalytics, GqlCodeScanningFindingsConnection, GqlCodeScanningFilterOptions } from "@/lib/shared/graphql/types"
import { ScanRunningBanner } from "@/components/shared/ScanRunningBanner"
import { DashboardTabs } from "@/components/shared/DashboardTabs"
import { CodeScanningOverviewTab, type CodeScanningOverviewFilter } from "./overview-tab"
import { CodeScanningInsightsTab } from "./insights-tab"
import { CodeScanningHealthTab } from "./health-tab"
import { CodeScanningRepoGroupedFindings } from "./code-scanning-repo-grouped-findings"
import { CodeScanningFindingDrawer } from "./code-scanning-finding-drawer"
import { CodeScanningFindingsSearchBar } from "./code-scanning-findings-search-bar"
import { CodeScanningContent } from "@/app/(app)/settings/code/CodeScanningContent"

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

type CodeScanningTabId = "overview" | "findings" | "insights" | "health" | "settings"

/** Map GraphQL camelCase finding to the snake_case CodeScanningFinding shape used by FindingsTab. */
function gqlToCodeScanningFinding(g: GqlCodeScanningFindingsConnection["items"][0]): CodeScanningFinding {
  return {
    identity_key: g.id,
    repo_full_name: g.repoFullName,
    file_path: g.filePath,
    start_line: g.line,
    end_line: g.line,
    rule_id: g.ruleId,
    rule_name: g.ruleName,
    severity: g.severity as CodeScanningFinding["severity"],
    confidence: g.confidence ?? "",
    category: g.category ?? "",
    cwe: g.cwe ?? [],
    message: g.message,
    snippet: g.snippet ?? "",
    fix_suggestion: g.fixSuggestion ?? undefined,
    state: g.state as CodeScanningFinding["state"],
    first_seen_at: g.firstSeenAt ?? undefined,
    fixed_at: g.fixedAt ?? undefined,
    language: g.language ?? undefined,
    code_window: g.codeWindow ?? undefined,
    ai_review: g.aiReview
      ? {
          verdict: g.aiReview.verdict,
          explanation: g.aiReview.explanation,
          reasoning: g.aiReview.reasoning ?? undefined,
          confidence: g.aiReview.confidence ?? undefined,
        }
      : undefined,
    code_flows: g.codeFlows ?? undefined,
    reachability: g.reachability
      ? {
          verdict: g.reachability.verdict as "reachable" | "unreachable" | "unknown",
          entry_point: g.reachability.entryPoint ?? undefined,
          call_chain: g.reachability.callChain ?? undefined,
        }
      : undefined,
    introduced_by_commit_sha: g.introducedByCommitSha ?? null,
    introduced_by_author: g.introducedByAuthor ?? null,
    introduced_at: g.introducedAt ?? null,
    introduced_by_pr_url: g.introducedByPrUrl ?? null,
  }
}

const RUNNING_STATUSES = new Set<CodeScanningScanRun["status"]>(["queued", "running", "ingesting", "ai_review"])
const BANNER_STATUSES = new Set<CodeScanningScanRun["status"]>(["queued", "running", "ingesting", "ai_review", "failed"])

const DISMISS_REASONS: Array<{ value: string; label: string }> = [
  { value: "Fix started", label: "Fix started" },
  { value: "Risk is tolerable", label: "Risk is tolerable" },
  { value: "Alert is inaccurate", label: "Alert is inaccurate" },
  { value: "Vulnerable code is not used", label: "Vulnerable code is not used" },
]

// ---------------------------------------------------------------------------
// Bulk Action Bar
// ---------------------------------------------------------------------------

interface BulkBarProps {
  selectedKeys: Set<string>
  findings: CodeScanningFinding[]
  org: string
  onComplete: () => void
  onClear: () => void
}

function BulkActionBar({ selectedKeys, findings, org, onComplete, onClear }: BulkBarProps) {
  const [dismissReason, setDismissReason] = useState("Fix started")
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const selectedFindings = useMemo(
    () => findings.filter((f) => selectedKeys.has(f.identity_key)),
    [findings, selectedKeys],
  )
  const canDismiss = selectedFindings.some((f) => f.state === "open" || f.state === "awaiting_fix")
  const canReopen = selectedFindings.some((f) => f.state === "dismissed")

  async function handleBulkAction(action: "dismiss" | "reopen") {
    setIsSubmitting(true)
    setError(null)
    try {
      const { ok, payload } = await bulkReviewCodeScanningFindings(org, Array.from(selectedKeys), action, action === "dismiss" ? dismissReason : undefined)
      if (!ok || payload.error) {
        setError(payload.error ?? `Failed to ${action} findings`)
      } else {
        onComplete()
        onClear()
      }
    } catch {
      setError("Network error")
    } finally {
      setIsSubmitting(false)
    }
  }

  if (selectedKeys.size === 0) return null

  return (
    <div className="flex flex-wrap items-center gap-3 rounded-lg border border-[var(--color-accent-border)] bg-[var(--color-accent-subtle)] px-4 py-3">
      <span className="text-sm font-medium text-[var(--color-text-primary)]">{selectedKeys.size} selected</span>
      {error && <span className="text-xs text-[var(--color-severity-critical)]">{error}</span>}
      <div className="ml-auto flex flex-wrap items-center gap-2">
        {canDismiss && (
          <>
            <select
              value={dismissReason}
              onChange={(e) => setDismissReason(e.target.value)}
              className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]"
            >
              {DISMISS_REASONS.map((r) => (
                <option key={r.value} value={r.value}>{r.label}</option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => void handleBulkAction("dismiss")}
              disabled={isSubmitting}
              className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-sm font-medium text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)] disabled:opacity-50"
            >
              Dismiss Selected
            </button>
          </>
        )}
        {canReopen && (
          <button
            type="button"
            onClick={() => void handleBulkAction("reopen")}
            disabled={isSubmitting}
            className="rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-sm font-medium text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)] disabled:opacity-50"
          >
            Reopen Selected
          </button>
        )}
        <button
          type="button"
          onClick={onClear}
          className="rounded-lg px-3 py-1.5 text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
        >
          Clear
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Findings Tab
// ---------------------------------------------------------------------------

interface FindingsTabProps {
  findings: CodeScanningFinding[]
  isLoading: boolean
  error: string | null
  primaryOrg: string
  onActionComplete: () => Promise<void>
  initialSeverity?: string
  initialState?: string
  initialRepo?: string
  initialRuleId?: string
  initialAgeBucket?: string
  lastScanDate?: string | null
}

function FindingsTab({ findings, isLoading, error, primaryOrg, onActionComplete, initialSeverity, initialState, initialRepo, initialRuleId, initialAgeBucket, lastScanDate }: FindingsTabProps) {
  const [filterSeverity, setFilterSeverity] = useState<string[]>(initialSeverity ? [initialSeverity] : [])
  const [filterState, setFilterState] = useState(initialState === undefined ? "" : initialState)
  const [filterRepo, setFilterRepo] = useState(initialRepo ?? "")
  const [filterRuleId, setFilterRuleId] = useState(initialRuleId ?? "")
  const [filterAgeBucket, setFilterAgeBucket] = useState(initialAgeBucket ?? "")
  const [filterRepoExact, setFilterRepoExact] = useState("")
  const [filterLanguage, setFilterLanguage] = useState("")
  const [filterReachability, setFilterReachability] = useState("")
  const [filterConfidence, setFilterConfidence] = useState("")
  const [filterNewFindings, setFilterNewFindings] = useState(false)
  const [viewMode, setViewMode] = useState("list")
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set())
  const [drawerFinding, setDrawerFinding] = useState<CodeScanningFinding | null>(null)

  const repos = useMemo(() => {
    const s = new Set(findings.map((f) => f.repo_full_name).filter(Boolean))
    return Array.from(s).sort()
  }, [findings])

  const languages = useMemo(() => {
    const s = new Set(findings.map((f) => f.language ?? "").filter(Boolean))
    return Array.from(s).sort()
  }, [findings])

  useEffect(() => {
    setFilterSeverity(initialSeverity ? [initialSeverity] : [])
  }, [initialSeverity])

  useEffect(() => {
    setFilterState(initialState === undefined ? "" : initialState)
  }, [initialState])

  useEffect(() => {
    setFilterRepo(initialRepo ?? "")
  }, [initialRepo])

  useEffect(() => {
    setFilterRuleId(initialRuleId ?? "")
  }, [initialRuleId])

  useEffect(() => {
    setFilterAgeBucket(initialAgeBucket ?? "")
  }, [initialAgeBucket])

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (filterSeverity.length && !filterSeverity.includes(f.severity)) return false
      if (filterState && f.state !== filterState) return false
      if (filterRepo) {
        const q = filterRepo.toLowerCase()
        if (
          !f.repo_full_name.toLowerCase().includes(q) &&
          !f.file_path.toLowerCase().includes(q) &&
          !f.rule_name.toLowerCase().includes(q)
        ) return false
      }
      if (filterRepoExact && f.repo_full_name !== filterRepoExact) return false
      if (filterLanguage && (f.language ?? "") !== filterLanguage) return false
      if (filterReachability) {
        const verdict = f.reachability?.verdict ?? "unknown"
        if (verdict !== filterReachability) return false
      }
      if (filterConfidence && (f.confidence ?? "") !== filterConfidence) return false
      if (filterNewFindings && lastScanDate && (!f.first_seen_at || f.first_seen_at < lastScanDate)) return false
      if (filterRuleId && f.rule_id !== filterRuleId) return false
      if (filterAgeBucket) {
        const ageMs = Date.now() - new Date(f.first_seen_at ?? 0).getTime()
        const days = ageMs / (1000 * 60 * 60 * 24)
        if (filterAgeBucket === "< 7 days" && days >= 7) return false
        if (filterAgeBucket === "7–30 days" && (days < 7 || days >= 30)) return false
        if (filterAgeBucket === "30–90 days" && (days < 30 || days >= 90)) return false
        if (filterAgeBucket === "> 90 days" && days < 90) return false
      }
      return true
    })
  }, [findings, filterSeverity, filterState, filterRepo, filterRepoExact, filterLanguage, filterReachability, filterConfidence, filterNewFindings, lastScanDate, filterRuleId, filterAgeBucket])

  function toggleSelect(key: string) {
    setSelectedKeys((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  function handleSetSelected(keys: string[], shouldSelect: boolean) {
    setSelectedKeys((prev) => {
      const next = new Set(prev)
      if (shouldSelect) keys.forEach((k) => next.add(k))
      else keys.forEach((k) => next.delete(k))
      return next
    })
  }

  return (
    <div className="relative space-y-3">
      {/* Backdrop — closes drawer when clicking outside on mobile */}
      {drawerFinding !== null && (
        <div
          className="fixed inset-0 z-30 bg-[var(--color-overlay)] xl:bg-transparent"
          onClick={() => setDrawerFinding(null)}
          aria-hidden="true"
        />
      )}

      {/* ── Findings container — matches Secrets Review tab pattern ─────────── */}
      <div className="overflow-hidden rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)]">

        <CodeScanningFindingsSearchBar
          search={filterRepo}
          filterState={filterState}
          filterSeverity={filterSeverity}
          filterRepoExact={filterRepoExact}
          filterLanguage={filterLanguage}
          filterReachability={filterReachability}
          filterConfidence={filterConfidence}
          filterNewFindings={filterNewFindings}
          filterRuleId={filterRuleId}
          filterAgeBucket={filterAgeBucket}
          viewMode={viewMode}
          repos={repos}
          languages={languages}
          hasActiveFilters={Boolean(filterSeverity.length || filterRepo || filterRepoExact || filterLanguage || filterReachability || filterConfidence || filterNewFindings || filterRuleId || filterAgeBucket || filterState)}
          onSearchChange={setFilterRepo}
          onFilterStateChange={setFilterState}
          onFilterSeverityChange={setFilterSeverity}
          onFilterRepoExactChange={setFilterRepoExact}
          onFilterLanguageChange={setFilterLanguage}
          onFilterReachabilityChange={setFilterReachability}
          onFilterConfidenceChange={setFilterConfidence}
          onFilterNewFindingsChange={setFilterNewFindings}
          onFilterRuleIdChange={setFilterRuleId}
          onFilterAgeBucketChange={setFilterAgeBucket}
          onViewModeChange={setViewMode}
          onResetFilters={() => { setFilterSeverity([]); setFilterState(""); setFilterRepo(""); setFilterRepoExact(""); setFilterLanguage(""); setFilterReachability(""); setFilterConfidence(""); setFilterNewFindings(false); setFilterRuleId(""); setFilterAgeBucket(""); setViewMode("list") }}
        />

        {/* Bulk action bar — renders null when nothing selected */}
        <BulkActionBar
          selectedKeys={selectedKeys}
          findings={filteredFindings}
          org={primaryOrg}
          onComplete={() => void onActionComplete()}
          onClear={() => setSelectedKeys(new Set())}
        />

        {/* Content */}
        {isLoading ? (
          <div className="flex items-center justify-center py-16">
            <p className="text-sm text-[var(--color-text-secondary)]">Loading findings...</p>
          </div>
        ) : error ? (
          <div className="flex items-center justify-center py-16">
            <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>
          </div>
        ) : (
          <CodeScanningRepoGroupedFindings
            rows={filteredFindings}
            selected={selectedKeys}
            activeFinding={drawerFinding}
            onToggleSelect={toggleSelect}
            onSetSelected={handleSetSelected}
            onSelectFinding={setDrawerFinding}
            totalCount={filteredFindings.length}
            initialExpandedRepo={initialRepo}
            groupBy={
              viewMode === "repository"
                ? (f) => f.repo_full_name
                : viewMode === "rule"
                  ? (f) => f.rule_id
                  : undefined
            }
            renderGroupLabel={
              viewMode === "repository"
                ? (label) => {
                    const slash = label.indexOf("/")
                    if (slash === -1) return label
                    return (
                      <>
                        <span className="font-normal text-[var(--color-text-secondary)]">{label.slice(0, slash)}</span>
                        <span className="font-normal text-[var(--color-text-secondary)]"> / </span>
                        {label.slice(slash + 1)}
                      </>
                    )
                  }
                : viewMode === "rule"
                  ? (ruleId) => {
                      const match = filteredFindings.find((f) => f.rule_id === ruleId)
                      return match?.rule_name ?? ruleId
                    }
                  : undefined
            }
            hideColumns={
              viewMode === "repository"
                ? new Set(["repository"])
                : viewMode === "rule"
                  ? new Set(["rule"])
                  : undefined
            }
            groupLabel={
              viewMode === "repository" ? "repos" : viewMode === "rule" ? "rules" : undefined
            }
          />
        )}
      </div>


      <CodeScanningFindingDrawer
        finding={drawerFinding}
        org={primaryOrg}
        onClose={() => setDrawerFinding(null)}
        onActionComplete={() => {
          setSelectedKeys(new Set())
          void onActionComplete()
        }}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main Dashboard View
// ---------------------------------------------------------------------------

export function CodeScanningDashboardView({ org, initialTab, canEdit, prerequisitesMet }: { org: string; initialTab?: string; canEdit?: boolean; prerequisitesMet?: boolean }) {
  const orgQuery = useMemo(() => buildOrgQuery(org), [org])
  const primaryOrg = org.split(",")[0].trim()

  const [activeTab, setActiveTab] = useState<CodeScanningTabId>((initialTab as CodeScanningTabId) ?? "overview")
  useEffect(() => {
    if (!prerequisitesMet) return
    const viewed = localStorage.getItem("tool_settings_viewed_code_scanning")
    if (viewed) {
      if (activeTab === "settings") setActiveTab("overview")
    } else {
      if (activeTab !== "settings") setActiveTab("settings")
      localStorage.setItem("tool_settings_viewed_code_scanning", "1")
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps
  const [findingsInitialFilter, setFindingsInitialFilter] = useState<{
    severity?: string
    state?: string
    repo?: string
    ruleId?: string
    ageBucket?: string
  }>({})
  const [error, setError] = useState<string | null>(null)
  const [latestRun, setLatestRun] = useState<CodeScanningScanRun | null>(null)
  const [lastCompleted, setLastCompleted] = useState<CodeScanningScanRun | null>(null)
  const [history, setHistory] = useState<CodeScanningScanRun[]>([])
  const [coverageGaps, setCoverageGaps] = useState<Array<{ repository: string; reason: string; lastScannedAt: string | null }>>([])
  const [nowMs, setNowMs] = useState(() => Date.now())

  // ── GraphQL state ────────────────────────────────────────────────────────
  const [gqlAnalytics, setGqlAnalytics] = useState<GqlCodeScanningAnalytics | null>(null)
  const [gqlFindings, setGqlFindings] = useState<GqlCodeScanningFindingsConnection | null>(null)
  const [filterOptions, setFilterOptions] = useState<GqlCodeScanningFilterOptions | null>(null)
  const [findingsPageNum, setFindingsPageNum] = useState(1)

  const isRunning = Boolean(latestRun && RUNNING_STATUSES.has(latestRun.status))
  const showBanner = Boolean(latestRun && BANNER_STATUSES.has(latestRun.status))

  useEffect(() => {
    if (!isRunning) return
    const id = window.setInterval(() => setNowMs(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [isRunning])

  const loadRuns = useCallback(async () => {
    if (!orgQuery) return
    try {
      const { payload } = await fetchCodeScanningRuns(orgQuery)
      if (!payload.error) {
        setLatestRun(payload.latest ?? null)
        setLastCompleted(payload.lastCompleted ?? null)
      }
    } catch {
      // ignore
    }
  }, [orgQuery])

  const loadHistory = useCallback(async () => {
    if (!orgQuery) return
    try {
      const { payload } = await fetchCodeScanningHistory(orgQuery)
      setHistory(payload.history ?? [])
      setCoverageGaps(payload.coverageGaps ?? [])
    } catch {
      // ignore
    }
  }, [orgQuery])

  // ── GraphQL: load analytics ──────────────────────────────────────────────
  const loadAnalytics = useCallback(async () => {
    try {
      const data = await gqlQuery<{ codeScanningAnalytics: GqlCodeScanningAnalytics }>(
        CODE_SCANNING_ANALYTICS_QUERY, { org }
      )
      setGqlAnalytics(data.codeScanningAnalytics)
    } catch (err) {
      if (err instanceof GraphQLQueryError && err.code === "AUTH_ERROR") {
        setError("Session expired — please refresh the page")
      }
    }
  }, [org])

  // ── GraphQL: load paginated findings ─────────────────────────────────────
  const loadGqlFindings = useCallback(async () => {
    try {
      const data = await gqlQuery<{ codeScanningFindings: GqlCodeScanningFindingsConnection }>(
        CODE_SCANNING_FINDINGS_QUERY,
        {
          org,
          page: findingsPageNum,
          perPage: 100,
          severity: findingsInitialFilter.severity || undefined,
          state: findingsInitialFilter.state || undefined,
          ruleId: findingsInitialFilter.ruleId || undefined,
          repository: findingsInitialFilter.repo || undefined,
          ageBucket: findingsInitialFilter.ageBucket || undefined,
        }
      )
      setGqlFindings(data.codeScanningFindings)
    } catch (err) {
      if (err instanceof GraphQLQueryError && err.code === "AUTH_ERROR") {
        setError("Session expired — please refresh the page")
      }
    }
  }, [org, findingsPageNum, findingsInitialFilter])

  // ── GraphQL: load filter options ─────────────────────────────────────────
  const loadFilterOptions = useCallback(async () => {
    try {
      const data = await gqlQuery<{ codeScanningFilterOptions: GqlCodeScanningFilterOptions }>(
        CODE_SCANNING_FILTER_OPTIONS_QUERY, { org }
      )
      setFilterOptions(data.codeScanningFilterOptions)
    } catch {
      // ignore
    }
  }, [org])

  // ── Initial load ────────────────────────────────────────────────────────
  useEffect(() => {
    void loadRuns()
    void loadHistory()
    void loadAnalytics()
  }, [loadRuns, loadHistory, loadAnalytics])

  // Load tab-specific data on tab switch
  useEffect(() => {
    if (activeTab === "findings") {
      void loadGqlFindings()
      void loadFilterOptions()
    }
  }, [activeTab, loadGqlFindings, loadFilterOptions])

  // ── SSE: real-time scan progress ──────────────────────────────────────────
  useSSE("scan.progress", (data: ScanProgressEvent) => {
    if (data.tool !== "code_scanning") return
    if ((data as any)._refresh) { void loadRuns(); return }
    setLatestRun((prev) => {
      if (!prev || prev.id !== data.runId) { void loadRuns(); return prev }
      if (prev.status === "completed" || prev.status === "failed" || prev.status === "cancelled") return prev
      return { ...prev, status: "running", progress: data.progress, logTail: data.logTail }
    })
  })

  useSSE("scan.completed", (data: ScanCompletedEvent) => {
    if (data.tool !== "code_scanning") return
    void loadRuns()
    void loadHistory()
    void loadAnalytics()
    if (activeTab === "findings") {
      void loadGqlFindings()
      void loadFilterOptions()
    }
  })

  useSSE("scan.failed", (data: ScanFailedEvent) => {
    if (data.tool !== "code_scanning") return
    void loadRuns()
  })


  async function handleActionComplete() {
    void loadGqlFindings()
    void loadAnalytics()
  }

  return (
    <div className="space-y-6">
      {showBanner && latestRun && (
        <ScanRunningBanner
          organization={latestRun.org}
          status={latestRun.status}
          progress={latestRun.progress}
          logTail={latestRun.logTail}
          startedAt={latestRun.startedAt ?? null}
          createdAt={latestRun.createdAt ?? null}
          nowMs={nowMs}
          commandLabel={`root@scanner:~$ ./run-code-scan.sh --org ${latestRun.org}`}
          scanLabel="Code scan"
          extraStages={{ scanning: "Scanning Repositories" }}
        />
      )}

      <DashboardTabs tabs={[{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "insights", label: "Insights" }, { id: "health", label: "Health" }, { id: "settings", label: "Settings" }] as const} activeTab={activeTab} onChange={setActiveTab} />

      {activeTab === "overview" && (
        <CodeScanningOverviewTab
          analytics={gqlAnalytics}
          onGoToFindings={(opts: CodeScanningOverviewFilter) => {
            setFindingsInitialFilter(opts)
            setFindingsPageNum(1)
            setActiveTab("findings")
            window.scrollTo({ top: 0 })
          }}
        />
      )}

      {activeTab === "insights" && (
        <CodeScanningInsightsTab
          analytics={gqlAnalytics}
          onGoToFindings={(opts) => {
            setFindingsInitialFilter(opts ?? {})
            setFindingsPageNum(1)
            setActiveTab("findings")
            window.scrollTo({ top: 0 })
          }}
        />
      )}

      {activeTab === "health" && (
        <CodeScanningHealthTab
          runHistory={history}
          analytics={gqlAnalytics}
          coverageGaps={coverageGaps}
        />
      )}

      {activeTab === "findings" && (
        <FindingsTab
          findings={(gqlFindings?.items ?? []).map(gqlToCodeScanningFinding)}
          isLoading={!gqlFindings}
          error={error}
          primaryOrg={primaryOrg}
          onActionComplete={handleActionComplete}
          initialSeverity={findingsInitialFilter.severity}
          initialState={findingsInitialFilter.state}
          initialRepo={findingsInitialFilter.repo}
          initialRuleId={findingsInitialFilter.ruleId}
          initialAgeBucket={findingsInitialFilter.ageBucket}
          lastScanDate={lastCompleted?.finishedAt ?? null}
        />
      )}

      {activeTab === "settings" && (
        canEdit ? (
          <CodeScanningContent canEdit={canEdit} />
        ) : (
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center">
            <p className="text-sm text-[var(--color-text-secondary)]">You need admin access to manage tool settings.</p>
          </div>
        )
      )}
    </div>
  )
}
