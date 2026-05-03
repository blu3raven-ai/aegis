"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import type { DependenciesHealthRunEntry } from "@/lib/shared/dependencies/types"
import { type OpenFindingsFilterOpts } from "@/lib/shared/container-scanning/utils"
import { CONTAINER_SCANNING_API } from "@/lib/shared/api-paths"
import { readJsonResponse } from "@/lib/shared/client-json"
import { buildOrgQuery } from "@/lib/shared/org-query"
import { fetchContainerScanningRuns, bulkReviewContainerScanningFindings, dismissContainerScanningFinding, reopenContainerScanningFinding, type ContainerScanningRun } from "@/lib/client/container-scanning-client"
import { DashboardTabs } from "@/components/shared/DashboardTabs"
import { ContainerScanningContent } from "@/app/(app)/settings/containers/ContainerScanningContent"
import { DependenciesOverviewTab } from "@/app/(app)/dependencies/_components/overview-tab"
import { DependenciesFindingsTab } from "@/app/(app)/dependencies/_components/findings-tab"
import { CONTAINER_VIEW_MODES } from "@/components/shared/ViewModeToggle"
import { DependenciesInsightsTab } from "@/app/(app)/dependencies/_components/insights-tab"
import { DependenciesHealthTab } from "@/app/(app)/dependencies/_components/health-tab"
import { useCurrentUser } from "@/lib/client/auth"
import { can } from "@/lib/shared/auth/roles.ts"
import { ScanRunningBanner } from "@/components/shared/ScanRunningBanner"
import { useSSE } from "@/components/providers/SSEProvider"
import type { ScanProgressEvent, ScanCompletedEvent, ScanFailedEvent } from "@/lib/shared/sse-types"
import { gqlQuery, GraphQLQueryError } from "@/lib/client/graphql-client"
import { CONTAINER_ANALYTICS_QUERY, CONTAINER_FINDINGS_QUERY, CONTAINER_FILTER_OPTIONS_QUERY } from "@/lib/shared/graphql/queries"
import type { GqlContainerAnalytics, GqlContainerFindingsConnection, GqlFilterOptions, GqlDependenciesAnalytics, GqlDependenciesFindingsConnection } from "@/lib/shared/graphql/types"

type ContainerScanningTabId = "overview" | "findings" | "insights" | "health" | "settings"

const RUNNING_STATUSES = new Set<ContainerScanningRun["status"]>(["queued", "running", "ingesting"])
const BANNER_STATUSES = new Set<ContainerScanningRun["status"]>(["queued", "running", "ingesting", "failed"])

export function ContainerScanningDashboardView({ org, initialTab, canEdit, prerequisitesMet }: { org: string; initialTab?: string; canEdit?: boolean; prerequisitesMet?: boolean }) {

  const [activeTab, setActiveTab] = useState<ContainerScanningTabId>((initialTab as ContainerScanningTabId) ?? "overview")
  useEffect(() => {
    if (!prerequisitesMet) return
    const viewed = localStorage.getItem("tool_settings_viewed_containerScanning")
    if (viewed) {
      if (activeTab === "settings") setActiveTab("overview")
    } else {
      if (activeTab !== "settings") setActiveTab("settings")
      localStorage.setItem("tool_settings_viewed_containerScanning", "1")
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps
  const { user } = useCurrentUser()
  const [history, setHistory] = useState<DependenciesHealthRunEntry[]>([])
  const [latestRun, setLatestRun] = useState<ContainerScanningRun | null>(null)
  const [lastCompleted, setLastCompleted] = useState<ContainerScanningRun | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [findingsState, setFindingsState] = useState("")
  const [findingsSeverity, setFindingsSeverity] = useState<string[]>([])
  const [findingsEcosystem, setFindingsEcosystem] = useState<string[]>([])
  const [findingsPackageSearch, setFindingsPackageSearch] = useState("")
  const [findingsRepository, setFindingsRepository] = useState("")
  const [findingsAgeBucket, setFindingsAgeBucket] = useState("")
  const [findingsViewMode, setFindingsViewMode] = useState("list")

  // ── GraphQL state ────────────────────────────────────────────────────────
  const [gqlAnalytics, setGqlAnalytics] = useState<GqlContainerAnalytics | null>(null)
  const [gqlFindings, setGqlFindings] = useState<GqlContainerFindingsConnection | null>(null)
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
      const { payload } = await fetchContainerScanningRuns(orgQuery)
      setLatestRun(payload.latest ?? null)
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
      const response = await fetch(`${CONTAINER_SCANNING_API.history}?${orgQuery}`, { cache: "no-store" })
      const payload = await readJsonResponse<{ history: DependenciesHealthRunEntry[] }>(response)
      setHistory(payload.history || [])
    } catch {
      // ignore
    }
  }, [orgQuery])

  // ── GraphQL: load analytics (overview/insights tabs) ─────────────────────
  const loadAnalytics = useCallback(async () => {
    try {
      const data = await gqlQuery<{ containerAnalytics: GqlContainerAnalytics }>(
        CONTAINER_ANALYTICS_QUERY, { org }
      )
      setGqlAnalytics(data.containerAnalytics)
    } catch (err) {
      if (err instanceof GraphQLQueryError && err.code === "AUTH_ERROR") {
        setError("Session expired — please refresh the page")
      }
    }
  }, [org])

  // ── GraphQL: load filter options ────────────────────────────────────────
  const loadFilterOptions = useCallback(async () => {
    try {
      const data = await gqlQuery<{ containerFilterOptions: GqlFilterOptions }>(
        CONTAINER_FILTER_OPTIONS_QUERY, { org }
      )
      setFilterOptions(data.containerFilterOptions)
    } catch {
      // ignore
    }
  }, [org])

  // ── GraphQL: load paginated findings ─────────────────────────────────────
  const loadGqlFindings = useCallback(async () => {
    try {
      const data = await gqlQuery<{ containerFindings: GqlContainerFindingsConnection }>(
        CONTAINER_FINDINGS_QUERY,
        {
          org,
          page: findingsPageNum,
          perPage: findingsPerPage,
          severity: findingsSeverity.length === 1 ? findingsSeverity[0] : undefined,
          state: findingsState || undefined,
          ecosystem: findingsEcosystem.length ? findingsEcosystem : undefined,
          repository: findingsRepository || undefined,
          packageSearch: findingsPackageSearch || undefined,
          ageBucket: findingsAgeBucket || undefined,
        }
      )
      setGqlFindings(data.containerFindings)
    } catch {
      // ignore
    }
  }, [org, findingsPageNum, findingsPerPage, findingsSeverity, findingsState, findingsEcosystem, findingsRepository, findingsPackageSearch, findingsAgeBucket])

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
    if (data.tool !== "container_scanning") return
    if ((data as any)._refresh) { void loadRuns(); return }
    setLatestRun((prev) => {
      if (!prev || prev.id !== data.runId) { void loadRuns(); return prev }
      if (prev.status === "completed" || prev.status === "failed" || prev.status === "cancelled") return prev
      return { ...prev, status: "running", progress: data.progress, logTail: data.logTail }
    })
  })

  useSSE("scan.completed", (data: ScanCompletedEvent) => {
    if (data.tool !== "container_scanning") return
    void loadRuns()
    void loadAnalytics()
    void loadFilterOptions()
    if (activeTab === "findings") void loadGqlFindings()
    void loadHistory()
  })

  useSSE("scan.failed", (data: ScanFailedEvent) => {
    if (data.tool !== "container_scanning") return
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
    setFindingsState("open")
    setFindingsSeverity([])
    setFindingsEcosystem([])
    setFindingsPackageSearch("")
    setFindingsRepository("")
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

  // GqlContainerAnalytics and GqlDependenciesAnalytics share the same shape;
  // the Dependencies tab components accept GqlDependenciesAnalytics so we cast here.
  const analyticsForTabs = gqlAnalytics as unknown as GqlDependenciesAnalytics | null
  const findingsForTabs = gqlFindings as unknown as GqlDependenciesFindingsConnection | null

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
            commandLabel={`root@scanner:~$ ./run-container-scan.sh --org ${org}`}
            scanLabel="Container scan"
            extraStages={{ scanning: "Scanning Images", refreshing_advisories: "Refreshing Advisory Sources", matching: "Matching Vulnerabilities" }}
          />
        </div>
      )}

      <DashboardTabs tabs={[{ id: "overview", label: "Overview" }, { id: "findings", label: "Findings" }, { id: "insights", label: "Insights" }, { id: "health", label: "Health" }, { id: "settings", label: "Settings" }] as const} activeTab={activeTab} onChange={setActiveTab} />

      {activeTab === "overview" && (
        <DependenciesOverviewTab
          analytics={analyticsForTabs}
          activeSeverity={activeSeverity}
          onOpenFindingsFiltered={onOpenFindingsFiltered}
          onOpenHealth={onOpenHealth}
          entityLabel="image"
        />
      )}

      {activeTab === "findings" && (
        <DependenciesFindingsTab
          gqlFindings={findingsForTabs}
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
          ageBucketFilter={findingsAgeBucket}
          org={org}
          onStateFilterChange={setFindingsState}
          onSeverityFilterChange={setFindingsSeverity}
          onResetFilters={handleResetFilters}
          onFindingStateChange={async () => { void loadGqlFindings(); void loadAnalytics() }}
          bulkReviewFn={bulkReviewContainerScanningFindings}
          dismissFn={dismissContainerScanningFinding}
          reopenFn={reopenContainerScanningFinding}
          viewMode={findingsViewMode}
          viewModes={CONTAINER_VIEW_MODES}
          onViewModeChange={setFindingsViewMode}
        />
      )}

      {activeTab === "insights" && (
          <DependenciesInsightsTab
            analytics={analyticsForTabs}
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
          <ContainerScanningContent canEdit={canEdit} />
        ) : (
          <div className="rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center">
            <p className="text-sm text-[var(--color-text-secondary)]">You need admin access to manage tool settings.</p>
          </div>
        )
      )}
    </div>
  )
}
