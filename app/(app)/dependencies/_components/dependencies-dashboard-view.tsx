"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import type { DependenciesHealthRunEntry } from "@/lib/shared/dependencies/types"
import { type OpenFindingsFilterOpts } from "@/lib/shared/dependencies/utils"
import { DEPENDENCIES_API } from "@/lib/shared/api-paths"
import { readJsonResponse } from "@/lib/shared/client-json"
import { buildOrgQuery } from "@/lib/shared/org-query"
import { fetchDependenciesRuns, bulkReviewDependenciesFindings, dismissDependenciesFinding, reopenDependenciesFinding, type DependenciesScanRun } from "@/lib/client/dependencies-client"
import { DashboardTabs } from "@/components/shared/DashboardTabs"
import { DependenciesOverviewTab } from "@/app/(app)/dependencies/_components/overview-tab"
import { DependenciesFindingsTab } from "@/app/(app)/dependencies/_components/findings-tab"
import { DependenciesInsightsTab } from "@/app/(app)/dependencies/_components/insights-tab"
import { DependenciesHealthTab } from "@/app/(app)/dependencies/_components/health-tab"
import { DependenciesContent } from "@/app/(app)/settings/dependencies/DependenciesContent"
import { useCurrentUser } from "@/lib/client/auth"
import { can } from "@/lib/shared/auth/roles.ts"
import { ScanRunningBanner } from "@/components/shared/ScanRunningBanner"
import { useSSE } from "@/components/providers/SSEProvider"
import type { ScanProgressEvent, ScanCompletedEvent, ScanFailedEvent } from "@/lib/shared/sse-types"
import { gqlQuery, GraphQLQueryError } from "@/lib/client/graphql-client"
import { DEPENDENCIES_ANALYTICS_QUERY, DEPENDENCIES_FINDINGS_QUERY, DEPENDENCIES_FILTER_OPTIONS_QUERY } from "@/lib/shared/graphql/queries"
import type { GqlDependenciesAnalytics, GqlDependenciesFindingsConnection, GqlFilterOptions } from "@/lib/shared/graphql/types"

type DependenciesTabId = "overview" | "findings" | "insights" | "health" | "settings"

const RUNNING_STATUSES = new Set<DependenciesScanRun["status"]>(["queued", "running", "ingesting"])
const BANNER_STATUSES = new Set<DependenciesScanRun["status"]>(["queued", "running", "ingesting", "failed"])

export function DependenciesDashboardView({ org, initialTab, canEdit, prerequisitesMet }: { org: string; initialTab?: string; canEdit?: boolean; prerequisitesMet?: boolean }) {

  const [activeTab, setActiveTab] = useState<DependenciesTabId>((initialTab as DependenciesTabId) ?? "overview")
  useEffect(() => {
    if (!prerequisitesMet) return
    const viewed = localStorage.getItem("tool_settings_viewed_dependencies")
    if (viewed) {
      if (activeTab === "settings") setActiveTab("overview")
    } else {
      if (activeTab !== "settings") setActiveTab("settings")
      localStorage.setItem("tool_settings_viewed_dependencies", "1")
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps
  const { user } = useCurrentUser()
  const [history, setHistory] = useState<DependenciesHealthRunEntry[]>([])
  const [latestRun, setLatestRun] = useState<DependenciesScanRun | null>(null)
  const [lastCompleted, setLastCompleted] = useState<DependenciesScanRun | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [findingsState, setFindingsState] = useState("")
  const [findingsSeverity, setFindingsSeverity] = useState<string[]>([])
  const [findingsEcosystem, setFindingsEcosystem] = useState<string[]>([])
  const [findingsPackageSearch, setFindingsPackageSearch] = useState("")
  const [findingsRepository, setFindingsRepository] = useState("")
  const [findingsOrganization, setFindingsOrganization] = useState("")
  const [findingsFixAvailability, setFindingsFixAvailability] = useState("")
  const [findingsCvssRange, setFindingsCvssRange] = useState("")
  const [findingsNewSinceLastScan, setFindingsNewSinceLastScan] = useState(false)
  const [findingsAgeBucket, setFindingsAgeBucket] = useState("")
  const [findingsViewMode, setFindingsViewMode] = useState("list")

  // ── GraphQL state ────────────────────────────────────────────────────────
  const [gqlAnalytics, setGqlAnalytics] = useState<GqlDependenciesAnalytics | null>(null)
  const [gqlFindings, setGqlFindings] = useState<GqlDependenciesFindingsConnection | null>(null)
  const [filterOptions, setFilterOptions] = useState<GqlFilterOptions | null>(null)
  const [findingsPageNum, setFindingsPageNum] = useState(1)
  const [findingsPerPage, setFindingsPerPage] = useState(50)

  const orgQuery = useMemo(() => buildOrgQuery(org), [org])
  const isRunning = Boolean(latestRun && RUNNING_STATUSES.has(latestRun.status))
  const showBanner = Boolean(latestRun && BANNER_STATUSES.has(latestRun.status))

  const [nowMs, setNowMs] = useState(Date.now())

  useEffect(() => {
    if (!isRunning) return
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [isRunning])

  // ── Load run status ───────────────────────────────────────────────────────
  const loadRuns = useCallback(async () => {
    if (!orgQuery) return
    try {
      const { payload } = await fetchDependenciesRuns(orgQuery)
      setLatestRun(payload.latest ?? null)
      // Track last completed run for health tab timestamp
      if (payload.latest?.status === "completed") {
        setLastCompleted(payload.latest)
      }
    } catch {
      // ignore
    }
  }, [orgQuery])

  // ── Load history ──────────────────────────────────────────────────────────
  const loadHistory = useCallback(async () => {
    if (!orgQuery) return
    try {
      const response = await fetch(`${DEPENDENCIES_API.history}?${orgQuery}`, { cache: "no-store" })
      const payload = await readJsonResponse<{ history: DependenciesHealthRunEntry[] }>(response)
      setHistory(payload.history || [])
    } catch {
      // ignore
    }
  }, [orgQuery])

  // ── GraphQL: load analytics (overview/insights tabs) ─────────────────────
  const loadAnalytics = useCallback(async () => {
    try {
      const data = await gqlQuery<{ dependenciesAnalytics: GqlDependenciesAnalytics }>(
        DEPENDENCIES_ANALYTICS_QUERY, { org }
      )
      setGqlAnalytics(data.dependenciesAnalytics)
    } catch (err) {
      // Auth errors should surface — others silently degrade to zeros
      if (err instanceof GraphQLQueryError && err.code === "AUTH_ERROR") {
        setError("Session expired — please refresh the page")
      }
    }
  }, [org])

  // ── GraphQL: load filter options ────────────────────────────────────────
  const loadFilterOptions = useCallback(async () => {
    try {
      const data = await gqlQuery<{ dependenciesFilterOptions: GqlFilterOptions }>(
        DEPENDENCIES_FILTER_OPTIONS_QUERY, { org }
      )
      setFilterOptions(data.dependenciesFilterOptions)
    } catch {
      // ignore
    }
  }, [org])

  // ── GraphQL: load paginated findings ───────────────────────────────────
  const loadGqlFindings = useCallback(async () => {
    try {
      const data = await gqlQuery<{ dependenciesFindings: GqlDependenciesFindingsConnection }>(
        DEPENDENCIES_FINDINGS_QUERY,
        {
          org,
          // In grouped mode fetch all rows so groups aren't fragmented across server pages
          page: findingsViewMode !== "list" ? 1 : findingsPageNum,
          perPage: findingsViewMode !== "list" ? 10000 : findingsPerPage,
          severity: findingsSeverity.length === 1 ? findingsSeverity[0] : undefined,
          state: findingsState || undefined,
          ecosystem: findingsEcosystem.length ? findingsEcosystem : undefined,
          repository: findingsRepository || undefined,
          organization: findingsOrganization || undefined,
          packageSearch: findingsPackageSearch || undefined,
          fixAvailability: findingsFixAvailability || undefined,
          cvssRange: findingsCvssRange || undefined,
          ageBucket: findingsAgeBucket || undefined,
          newSinceLastScan: findingsNewSinceLastScan || undefined,
        }
      )
      setGqlFindings(data.dependenciesFindings)
    } catch {
      // ignore
    }
  }, [org, findingsViewMode, findingsPageNum, findingsPerPage, findingsSeverity, findingsState, findingsEcosystem, findingsRepository, findingsOrganization, findingsPackageSearch, findingsFixAvailability, findingsCvssRange, findingsAgeBucket, findingsNewSinceLastScan])

  // ── Initial load ──────────────────────────────────────────────────────────
  useEffect(() => {
    void loadRuns()
    void loadHistory()
    void loadFilterOptions()
  }, [loadRuns, loadHistory, loadFilterOptions])

  // Load analytics via GraphQL when overview or insights tab is active
  useEffect(() => {
    if (activeTab === "overview" || activeTab === "insights") void loadAnalytics()
  }, [activeTab, loadAnalytics])

  // Load paginated findings via GraphQL when findings tab is active
  useEffect(() => {
    if (activeTab === "findings") void loadGqlFindings()
  }, [activeTab, loadGqlFindings])


  // ── SSE: real-time scan progress ──────────────────────────────────────────
  useSSE("scan.progress", (data: ScanProgressEvent) => {
    if (data.tool !== "dependencies") return
    if ((data as any)._refresh) { void loadRuns(); return }
    setLatestRun((prev) => {
      if (!prev || prev.id !== data.runId) { void loadRuns(); return prev }
      if (prev.status === "completed" || prev.status === "failed" || prev.status === "cancelled") return prev
      return { ...prev, status: "running", progress: data.progress, logTail: data.logTail }
    })
  })

  useSSE("scan.completed", (data: ScanCompletedEvent) => {
    if (data.tool !== "dependencies") return
    void loadRuns()
    void loadAnalytics()
    void loadFilterOptions()
    if (activeTab === "findings") void loadGqlFindings()
    void loadHistory()
  })

  useSSE("scan.failed", (data: ScanFailedEvent) => {
    if (data.tool !== "dependencies") return
    void loadRuns()
  })

  const activeSeverity = findingsSeverity.length === 1 ? findingsSeverity[0] : ""

  // ── Navigation callbacks ──────────────────────────────────────────────────
  function onOpenFindingsFiltered(opts: OpenFindingsFilterOpts) {
    if (opts.state !== undefined) setFindingsState(opts.state)
    if (opts.severity !== undefined) setFindingsSeverity(opts.severity)
    if (opts.ecosystem !== undefined) setFindingsEcosystem(opts.ecosystem)
    if (opts.packageSearch !== undefined) setFindingsPackageSearch(opts.packageSearch)
    if (opts.repository !== undefined) setFindingsRepository(opts.repository)
    if (opts.ageBucket !== undefined) setFindingsAgeBucket(opts.ageBucket)
    setFindingsPageNum(1)
    setActiveTab("findings")
    window.scrollTo({ top: 0 })
  }

  function onOpenHealth() {
    setActiveTab("health")
    window.scrollTo({ top: 0 })
  }

  function handleResetFilters() {
    setFindingsState("")
    setFindingsSeverity([])
    setFindingsEcosystem([])
    setFindingsPackageSearch("")
    setFindingsRepository("")
    setFindingsOrganization("")
    setFindingsFixAvailability("")
    setFindingsCvssRange("")
    setFindingsNewSinceLastScan(false)
    setFindingsAgeBucket("")
    setFindingsViewMode("list")
    setFindingsPageNum(1)
  }

  const canRefresh = user ? can(user.role, "refresh_dashboard") : false

  // ── Error banner ──────────────────────────────────────────────────────────
  if (error && !gqlAnalytics) {
    return (
      <div className="rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-5 text-sm text-red-700 dark:text-red-400">
        <p className="font-medium mb-1">Failed to load dashboard</p>
        <p>{error}</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {showBanner && latestRun && (
        <div className="mb-6">
          <ScanRunningBanner
            organization={org}
            status={latestRun.status}
            progress={latestRun.progress}
            logTail={latestRun.logTail}
            startedAt={latestRun.startedAt ?? null}
            createdAt={latestRun.createdAt ?? null}
            nowMs={nowMs}
            commandLabel={`root@scanner:~$ ./run-dependencies-scan.sh --org ${org}`}
            scanLabel="Dependencies scan"
            extraStages={{ scanning: "Scanning Repositories", refreshing_advisories: "Refreshing Advisory Sources", matching: "Matching Vulnerabilities" }}
          />
        </div>
      )}

      <DashboardTabs tabs={[{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "insights", label: "Insights" }, { id: "health", label: "Health" }, { id: "settings", label: "Settings" }] as const} activeTab={activeTab} onChange={setActiveTab} />

      {activeTab === "overview" && (
        <DependenciesOverviewTab
          analytics={gqlAnalytics}
          activeSeverity={activeSeverity}
          onOpenFindingsFiltered={onOpenFindingsFiltered}
          onOpenHealth={onOpenHealth}
        />
      )}

      {activeTab === "findings" && (
        <DependenciesFindingsTab
          gqlFindings={gqlFindings}
          filterOptions={filterOptions}
          findingsPage={findingsPageNum}
          findingsPerPage={findingsPerPage}
          onPageChange={setFindingsPageNum}
          onPerPageChange={(n) => { setFindingsPerPage(n); setFindingsPageNum(1) }}
          stateFilter={findingsState}
          severityFilter={findingsSeverity}
          ecosystemFilter={findingsEcosystem}
          packageSearchFilter={findingsPackageSearch}
          repositoryFilter={findingsRepository}
          organizationFilter={findingsOrganization}
          fixAvailabilityFilter={findingsFixAvailability}
          cvssRangeFilter={findingsCvssRange}
          newSinceLastScan={findingsNewSinceLastScan}
          lastScanDate={lastCompleted?.finishedAt ?? null}
          ageBucketFilter={findingsAgeBucket}
          org={org}
          onStateFilterChange={setFindingsState}
          onSeverityFilterChange={setFindingsSeverity}
          onEcosystemFilterChange={setFindingsEcosystem}
          onRepositoryFilterChange={setFindingsRepository}
          onOrganizationFilterChange={setFindingsOrganization}
          onFixAvailabilityFilterChange={setFindingsFixAvailability}
          onCvssRangeFilterChange={setFindingsCvssRange}
          onNewSinceLastScanChange={setFindingsNewSinceLastScan}
          onAgeBucketFilterChange={setFindingsAgeBucket}
          onResetFilters={handleResetFilters}
          onFindingStateChange={async () => { void loadGqlFindings(); void loadAnalytics() }}
          bulkReviewFn={bulkReviewDependenciesFindings}
          dismissFn={dismissDependenciesFinding}
          reopenFn={reopenDependenciesFinding}
          viewMode={findingsViewMode}
          onViewModeChange={setFindingsViewMode}
        />
      )}

      {activeTab === "insights" && (
          <DependenciesInsightsTab
            analytics={gqlAnalytics}
            onOpenFindingsFiltered={onOpenFindingsFiltered}
          />
      )}

      {activeTab === "health" && (
          <DependenciesHealthTab
            runHistory={history}
            lastCompletedAt={lastCompleted?.finishedAt ?? null}
            org={org}
            canRefresh={canRefresh}
          />
      )}

      {activeTab === "settings" && (
        canEdit ? (
          <DependenciesContent canEdit={canEdit} />
        ) : (
          <div className="rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center">
            <p className="text-sm text-[var(--color-text-secondary)]">You need admin access to manage tool settings.</p>
          </div>
        )
      )}
    </div>
  )
}
