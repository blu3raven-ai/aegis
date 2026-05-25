"use client"

import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import type {
  SecretFinding,
  SecretReviewStatus,
  SecretScanRun,
  SecretsHealthResponse,
  SecretsInsightsResponse,
  SecretsReviewQueueResponse,
  SecretSortOrder,
} from "@/lib/shared/secrets/types"
import { buildOrgQuery } from "@/lib/shared/org-query"
import { SECRETS_VIEW_MODES } from "@/components/shared/ViewModeToggle"
import { ScanRunningBanner } from "@/components/shared/ScanRunningBanner"
import { runProgressValue } from "@/lib/shared/secrets/dashboard-utils"
import { type SecretFindingRow } from "@/app/(app)/secrets/_components/repo-grouped-findings"
import { DashboardTabs } from "@/components/shared/DashboardTabs"
import { OverviewTab } from "@/app/(app)/secrets/_components/overview-tab"
import { ReviewTab } from "@/app/(app)/secrets/_components/review-tab"
import { InsightsTab } from "@/app/(app)/secrets/_components/insights-tab"
import { HealthTab } from "@/app/(app)/secrets/_components/health-tab"
import { SecretsContent } from "@/app/(app)/settings/secrets/SecretsContent"
import { fetchCurrentUser, type CurrentUser } from "@/lib/client/auth"
import { can } from "@/lib/shared/auth/roles.ts"
import {
  applySecretsReview,
  cancelSecretsRuns,
  fetchSecretsCodePreview,
  fetchSecretsHealth,
  fetchSecretsInsights,
  fetchSecretsReviewQueue,
  fetchSecretsRuns,
  type CodePreviewResponse,
  type ReviewUpdatePayload,
  startSecretsRuns,
} from "@/lib/client/secrets/dashboard-client"
import { useSSE } from "@/components/providers/SSEProvider"
import type { ScanProgressEvent, ScanCompletedEvent, ScanFailedEvent } from "@/lib/shared/sse-types"
import { gqlQuery, GraphQLQueryError } from "@/lib/client/graphql-client"
import { SECRET_FINDINGS_QUERY, SECRET_OVERVIEW_QUERY, SECRET_FILTER_OPTIONS_QUERY } from "@/lib/shared/graphql/queries"
import type { GqlSecretFindingsConnection, GqlSecretsOverview, GqlSecretsFilterOptions, GqlSecretFinding } from "@/lib/shared/graphql/types"
import {
  dedupeFindings,
  findingCommitDate,
  findingUiIdentity,
  formatTimestamp,
  matchesFindingFilters,
  uniqueFindingKey,
} from "@/lib/shared/secrets/dashboard-utils"

interface Props {
  orgs: string[]
  latestRun?: SecretScanRun | null
  onLatestRunUpdate?: (run: SecretScanRun | null) => void
  initialTab?: string
  canEdit?: boolean
  prerequisitesMet?: boolean
}

const RUNNING_STATUSES = new Set<SecretScanRun["status"]>(["queued", "running", "ingesting"])
const BANNER_STATUSES = new Set<SecretScanRun["status"]>(["queued", "running", "ingesting", "failed"])

type SecretsTabId = "overview" | "review" | "insights" | "health" | "settings"

function gqlToSecretFinding(g: GqlSecretFinding): SecretFinding {
  return {
    id: g.id,
    runId: "",
    organization: g.organization,
    repository: g.repository,
    source: g.source,
    detector: g.detector,
    secretSnippet: g.secretSnippet ?? "",
    filePath: g.filePath,
    line: g.line ?? 0,
    commit: g.commit ?? null,
    detectedAt: g.detectedAt ?? g.firstSeenAt ?? "",
    fingerprint: g.fingerprint ?? "",
    secretIdentity: g.secretIdentity ?? undefined,
    reviewStatus: g.reviewStatus as SecretFinding["reviewStatus"],
    classificationHistory: (g.classificationHistory ?? []).map(e => ({
      value: e.value as any,
      source: e.source as any,
      scanDepth: (e.scanDepth ?? undefined) as any,
      confidence: e.confidence ?? 0,
      runId: e.runId ?? "",
      scannedAt: e.scannedAt ?? "",
    })),
    riskScore: g.riskScore ?? undefined,
    occurrenceCount: g.occurrenceCount ?? undefined,
    confirmedAt: g.confirmedAt ?? undefined,
    resolvedAt: g.resolvedAt ?? undefined,
    raw: {},
  }
}

export function SecretsDashboardView({ orgs, latestRun: propsLatestRun, onLatestRunUpdate, initialTab, canEdit, prerequisitesMet }: Props) {

  const enabledOrgs = useMemo(() => orgs.filter(Boolean), [orgs])
  const orgQuery = useMemo(() => buildOrgQuery(enabledOrgs), [enabledOrgs])
  const [activeTab, setActiveTab] = useState<SecretsTabId>((initialTab as SecretsTabId) ?? "overview")
  useEffect(() => {
    if (!prerequisitesMet) return
    const viewed = localStorage.getItem("tool_settings_viewed_secrets")
    if (viewed) {
      if (activeTab === "settings") setActiveTab("overview")
    } else {
      if (activeTab !== "settings") setActiveTab("settings")
      localStorage.setItem("tool_settings_viewed_secrets", "1")
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps
  const [user, setUser] = useState<CurrentUser | null>(null)
  const [overview, setOverview] = useState<GqlSecretsOverview | null>(null)
  const [gqlFilterOptions, setGqlFilterOptions] = useState<GqlSecretsFilterOptions | null>(null)
  const [internalLatestRun, setInternalLatestRun] = useState<SecretScanRun | null>(null)
  const [lastCompletedRun, setLastCompletedRun] = useState<SecretScanRun | null>(null)
  const [reviewQueue, setReviewQueue] = useState<SecretsReviewQueueResponse["queue"]>([])
  const [insights, setInsights] = useState<SecretsInsightsResponse | null>(null)
  const [health, setHealth] = useState<SecretsHealthResponse | null>(null)
  const [isLoadingDashboardData, setIsLoadingDashboardData] = useState(false)
  const [dashboardDataError, setDashboardDataError] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [nowMs, setNowMs] = useState(() => Date.now())
  const [search, setSearch] = useState("")
  const [organization, setOrganization] = useState("")
  const [repository, setRepository] = useState("")
  const [source, setSource] = useState("")
  const [statusFilter, setStatusFilter] = useState("")
  const [keyType, setKeyType] = useState<string[]>([])
  const [ageBucket, setAgeBucket] = useState("")
  const [newFindings, setNewFindings] = useState(false)
  const [classificationFilter, setClassificationFilter] = useState<string[]>([])
  const [sortOrder, setSortOrder] = useState<"newest" | "oldest" | "occurrences" | "risk">("newest")
  const [reviewViewMode, setReviewViewMode] = useState("list")
  const [showRepeatedOnly, setShowRepeatedOnly] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [activeFinding, setActiveFinding] = useState<SecretFinding | null>(null)
  const [codePreview, setCodePreview] = useState<CodePreviewResponse | null>(null)
  const [isLoadingPreview, setIsLoadingPreview] = useState(false)
  const [previewError, setPreviewError] = useState<string | null>(null)
  const loadTabContentRef = useRef<() => Promise<void>>(async () => {})
  const hasLoadedActiveTabRef = useRef(false)

  // ── GraphQL state ────────────────────────────────────────────────────────
  const [gqlFindings, setGqlFindings] = useState<GqlSecretFindingsConnection | null>(null)
  const [findingsPageNum, setFindingsPageNum] = useState(1)
  const [findingsPerPage, setFindingsPerPage] = useState(50)

  const latestRun = propsLatestRun !== undefined ? propsLatestRun : internalLatestRun
  const setLatestRun = onLatestRunUpdate ?? setInternalLatestRun

  const isRunning = Boolean(latestRun && RUNNING_STATUSES.has(latestRun.status))
  const showBanner = Boolean(latestRun && BANNER_STATUSES.has(latestRun.status))

  useEffect(() => {
    void fetchCurrentUser().then(setUser)
  }, [])

  const loadLatestRuns = useCallback(async () => {
    if (!orgQuery || propsLatestRun !== undefined) return
    const { payload } = await fetchSecretsRuns(orgQuery)
    if (payload.error) {
      setError(payload.error)
      return
    }
    setLatestRun(payload.latest ?? null)
    if (payload.lastCompleted !== undefined) {
      setLastCompletedRun(payload.lastCompleted ?? null)
    }
  }, [orgQuery, propsLatestRun, setLatestRun])

  useEffect(() => {
    void loadLatestRuns()
  }, [loadLatestRuns])

  // ── GraphQL: load overview ───────────────────────────────────────────────
  const loadOverview = useCallback(async () => {
    if (!enabledOrgs[0]) return
    try {
      const data = await gqlQuery<{ secretsOverview: GqlSecretsOverview }>(
        SECRET_OVERVIEW_QUERY, { org: enabledOrgs[0] }
      )
      setOverview(data.secretsOverview)
    } catch (err) {
      if (err instanceof GraphQLQueryError && err.code === "AUTH_ERROR") {
        setError("Session expired — please refresh the page")
      } else {
        console.error("[secrets] overview query failed:", err)
      }
    }
  }, [enabledOrgs])

  const loadFilterOptions = useCallback(async () => {
    if (!enabledOrgs[0]) return
    try {
      const data = await gqlQuery<{ secretsFilterOptions: GqlSecretsFilterOptions }>(
        SECRET_FILTER_OPTIONS_QUERY, { org: enabledOrgs[0] }
      )
      setGqlFilterOptions(data.secretsFilterOptions)
    } catch {
      // ignore
    }
  }, [enabledOrgs])

  // ── GraphQL: load paginated findings ─────────────────────────────────────
  const loadGqlFindings = useCallback(async () => {
    if (!enabledOrgs[0]) return
    try {
      const data = await gqlQuery<{ secretFindings: GqlSecretFindingsConnection }>(
        SECRET_FINDINGS_QUERY,
        {
          org: enabledOrgs[0],
          // In grouped mode fetch all rows so groups aren't fragmented across server pages
          page: reviewViewMode !== "list" ? 1 : findingsPageNum,
          perPage: reviewViewMode !== "list" ? 10000 : findingsPerPage,
          reviewStatus: statusFilter || undefined,
          detector: keyType.length === 1 ? keyType[0] : undefined,
          repository: repository || undefined,
          organization: organization || undefined,
          source: source || undefined,
          search: search || undefined,
          classification: classificationFilter.length === 1 ? classificationFilter[0] : undefined,
          ageBucket: ageBucket || undefined,
          newSinceLastScan: newFindings || undefined,
          lastScanDate: lastCompletedRun?.finishedAt || undefined,
        }
      )
      setGqlFindings(data.secretFindings)
    } catch (err) {
      if (err instanceof GraphQLQueryError && err.code === "AUTH_ERROR") {
        setError("Session expired — please refresh the page")
      } else {
        console.error("[secrets] findings query failed:", err)
      }
    }
  }, [enabledOrgs, reviewViewMode, findingsPageNum, findingsPerPage, statusFilter, keyType, repository, organization, source, search, classificationFilter, ageBucket, newFindings, lastCompletedRun])

  useEffect(() => {
    let stopped = false

    async function loadDashboardData() {
      if (!orgQuery) return
      setDashboardDataError(null)
      setIsLoadingDashboardData(true)
      try {
        const [{ payload: reviewPayload }, { payload: insightsPayload }, { payload: healthPayload }] = await Promise.all([
          fetchSecretsReviewQueue(orgQuery),
          fetchSecretsInsights(orgQuery),
          fetchSecretsHealth(orgQuery),
        ])
        if (stopped) return
        if (reviewPayload.error || insightsPayload.error || healthPayload.error) {
          setDashboardDataError(reviewPayload.error ?? insightsPayload.error ?? healthPayload.error ?? "Failed to load dashboard data.")
          return
        }
        setReviewQueue(reviewPayload.queue ?? [])
        setInsights(insightsPayload)
        setHealth(healthPayload)
      } finally {
        if (!stopped) setIsLoadingDashboardData(false)
      }
    }

    async function loadTabContent() {
      setError(null)
      await Promise.all([loadOverview(), loadGqlFindings(), loadFilterOptions(), loadDashboardData()])
    }

    loadTabContentRef.current = async () => {
      if (stopped) return
      await loadTabContent()
    }

    void loadTabContent()

    return () => {
      stopped = true
    }
  }, [orgQuery, loadOverview, loadGqlFindings, loadFilterOptions])

  useEffect(() => {
    if (!hasLoadedActiveTabRef.current) {
      hasLoadedActiveTabRef.current = true
      return
    }
    void loadTabContentRef.current()
  }, [activeTab])

  async function refreshInsights(filters?: { source?: string; organization?: string }) {
    if (!orgQuery) return
    const { payload } = await fetchSecretsInsights(orgQuery, filters)
    if (payload.error) {
      setDashboardDataError(payload.error)
      return
    }
    setDashboardDataError(null)
    setInsights(payload)
  }

  // ── SSE: real-time scan progress ──────────────────────────────────────────
  useSSE("scan.progress", (data: ScanProgressEvent) => {
    if (data.tool !== "secrets") return
    if ((data as any)._refresh) { void loadLatestRuns(); return }
    if (!latestRun || latestRun.id !== data.runId) { void loadLatestRuns(); return }
    if (latestRun.status === "completed" || latestRun.status === "failed" || latestRun.status === "cancelled") return
    setLatestRun({ ...latestRun, status: "running", progress: { ...latestRun.progress, ...data.progress, stage: data.progress.stage as typeof latestRun.progress.stage }, logTail: data.logTail })
  })

  useSSE("scan.completed", (data: ScanCompletedEvent) => {
    if (data.tool !== "secrets") return
    void loadLatestRuns()
    void loadOverview()
    void loadGqlFindings()
    void loadFilterOptions()
    void loadTabContentRef.current()
  })

  useSSE("scan.failed", (data: ScanFailedEvent) => {
    if (data.tool !== "secrets") return
    void loadLatestRuns()
  })


  const canRun = user ? can(user.role, "run_scans") : false
  const canReview = user ? can(user.role, "review_findings") : false

  const rawFindings = useMemo(
    () => (gqlFindings?.items ?? []).map(gqlToSecretFinding),
    [gqlFindings]
  )
  const findings = useMemo(() => dedupeFindings(rawFindings), [rawFindings])
  const occurrenceCountByKey = useMemo(() => {
    const counts = new Map<string, number>()
    for (const finding of rawFindings) {
      const key = uniqueFindingKey(finding)
      counts.set(key, (counts.get(key) ?? 0) + 1)
    }
    return counts
  }, [rawFindings])
  const filterState = useMemo(
    () => ({
      organization,
      repository,
      source,
      statusFilter,
      keyType,
      ageBucket,
      newFindings,
      lastScanDate: lastCompletedRun?.finishedAt ?? null,
      search,
      nowMs,
      classificationFilter,
    }),
    [organization, repository, source, statusFilter, keyType, ageBucket, newFindings, lastCompletedRun?.finishedAt, search, nowMs, classificationFilter]
  )
  const organizations = useMemo(() => {
      const seen = new Map<string, string>()
      for (const org of [
        ...enabledOrgs,
        ...findings
          .filter((item) => matchesFindingFilters(item, filterState, { organization: true }))
          .map((item) => item.organization),
      ]) {
        if (!org) continue
        const key = org.toLowerCase()
        if (!seen.has(key)) seen.set(key, org)
      }
      return Array.from(seen.values()).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }))
    },
    [enabledOrgs, findings, filterState]
  )
  const repositories = useMemo(
    () =>
      Array.from(
        new Set(
          findings
            .filter((item) => matchesFindingFilters(item, filterState, { repository: true }))
            .map((item) => item.repository)
        )
      ).sort((a, b) => a.localeCompare(b)),
    [findings, filterState]
  )
  const sources = useMemo(
    () =>
      Array.from(
        new Set(
          findings
            .filter((item) => matchesFindingFilters(item, filterState, { source: true }))
            .map((item) => item.source)
        )
      ).sort((a, b) => a.localeCompare(b)),
    [findings, filterState]
  )
  const keyTypes = useMemo(
    () =>
      Array.from(
        new Set(
          findings
            .filter((item) => matchesFindingFilters(item, filterState, { keyType: true }))
            .map((item) => item.detector)
        )
      ).sort((a, b) => a.localeCompare(b)),
    [findings, filterState]
  )

  // Unfiltered orgs/sources for the Insights tab — always show all options regardless of
  // whatever status/keyType filter the user has active in the Review tab.
  const allOrganizations = useMemo(() => {
    const seen = new Map<string, string>()
    for (const org of [...enabledOrgs, ...findings.map((f) => f.organization)]) {
      if (!org) continue
      const key = org.toLowerCase()
      if (!seen.has(key)) seen.set(key, org)
    }
    return Array.from(seen.values()).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }))
  }, [enabledOrgs, findings])

  const allSources = useMemo(
    () => Array.from(new Set(findings.map((f) => f.source))).sort((a, b) => a.localeCompare(b)),
    [findings]
  )

  // Per-repo status counts derived from the same deduped findings used by the Review tab,
  // so the numbers in the Insights triage priority always match what Review shows.
  const findingCountsByRepo = useMemo(() => {
    const map = new Map<string, { newCount: number; confirmedCount: number }>()
    for (const finding of findings) {
      const key = `${finding.organization}/${finding.repository}`
      const existing = map.get(key) ?? { newCount: 0, confirmedCount: 0 }
      if (finding.reviewStatus === "new") existing.newCount++
      else if (finding.reviewStatus === "confirmed") existing.confirmedCount++
      map.set(key, existing)
    }
    return map
  }, [findings])

  const enrichedTriagePriority = useMemo(
    () =>
      (insights?.triagePriority ?? []).map((repo) => {
        const counts = findingCountsByRepo.get(`${repo.organization}/${repo.repository}`)
        if (!counts) return repo
        return { ...repo, unreviewedCount: counts.newCount, confirmedCount: counts.confirmedCount }
      }),
    [insights, findingCountsByRepo]
  )

  const filtered = useMemo(() => {
    return findings.filter((finding) => {
      if (!matchesFindingFilters(finding, filterState)) return false
      return !showRepeatedOnly || (occurrenceCountByKey.get(uniqueFindingKey(finding)) ?? 0) > 1
    })
  }, [findings, filterState, occurrenceCountByKey, showRepeatedOnly])

  const rawFiltered = useMemo(() => {
    return rawFindings.filter((finding) => {
      if (!matchesFindingFilters(finding, filterState)) return false
      return !showRepeatedOnly || (occurrenceCountByKey.get(uniqueFindingKey(finding)) ?? 0) > 1
    })
  }, [rawFindings, filterState, occurrenceCountByKey, showRepeatedOnly])

  // Dedupe by (secretIdentity/fingerprint, commit) — same secret at the same commit
  // counts once even if found in multiple files. Across different commits it still counts
  // separately, so this stays meaningfully larger than "Unique keys".
  const commitDedupedCount = useMemo(() => {
    const seen = new Set<string>()
    for (const finding of rawFiltered) {
      const key = `${finding.organization}:${finding.secretIdentity ?? finding.fingerprint}:${finding.commit ?? ""}`
      seen.add(key)
    }
    return seen.size
  }, [rawFiltered])

  const correlatedFindings = useMemo(() => {
    if (!activeFinding) return []
    const activeKey = uniqueFindingKey(activeFinding)
    const activeIdentity = findingUiIdentity(activeFinding)
    return rawFindings
      .filter((finding) => uniqueFindingKey(finding) === activeKey && findingUiIdentity(finding) !== activeIdentity)
      .sort((a, b) => {
        const left = findingCommitDate(a)?.getTime() ?? 0
        const right = findingCommitDate(b)?.getTime() ?? 0
        return right - left
      })
  }, [activeFinding, rawFindings])

  const sorted = useMemo(
    () =>
      [...filtered].sort((a, b) => {
        if (sortOrder === "oldest") {
          const left = findingCommitDate(a)?.getTime() ?? 0
          const right = findingCommitDate(b)?.getTime() ?? 0
          return left - right
        }
        if (sortOrder === "occurrences") {
          return (
            (occurrenceCountByKey.get(uniqueFindingKey(b)) ?? 0) -
            (occurrenceCountByKey.get(uniqueFindingKey(a)) ?? 0)
          )
        }
        if (sortOrder === "risk") {
          return (b.riskScore ?? 0) - (a.riskScore ?? 0)
        }
        // default: newest
        const left = findingCommitDate(a)?.getTime() ?? 0
        const right = findingCommitDate(b)?.getTime() ?? 0
        return right - left
      }),
    [filtered, sortOrder, occurrenceCountByKey]
  )

  const sortedRows = useMemo<SecretFindingRow[]>(
    () =>
      sorted.map((finding, index) => ({
        finding,
        rowKey: `${findingUiIdentity(finding)}::${index}`,
      })),
    [sorted]
  )

  const findingByRowKey = useMemo(() => new Map(sortedRows.map((row) => [row.rowKey, row.finding])), [sortedRows])
  const reviewQueueByFingerprint = useMemo(
    () => new Map(reviewQueue.map((finding) => [finding.fingerprint, finding])),
    [reviewQueue]
  )

  useEffect(() => {
    if (repository && !repositories.includes(repository)) {
      setRepository("")
    }
  }, [repository, repositories])

  useEffect(() => {
    if (source && !sources.includes(source)) {
      setSource("")
    }
  }, [source, sources])

  useEffect(() => {
    if (keyType.length === 1 && !keyTypes.includes(keyType[0])) {
      setKeyType([])
    }
  }, [keyType, keyTypes])

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    setSelected(new Set())
    setFindingsPageNum(1)
  }, [organization, repository, source, statusFilter, JSON.stringify(keyType), showRepeatedOnly, search, classificationFilter, ageBucket, newFindings])

  useEffect(() => {
    if (!activeFinding) return
    const activeKey = findingUiIdentity(activeFinding)
    if (!rawFindings.some((finding) => findingUiIdentity(finding) === activeKey)) {
      setActiveFinding(null)
      setCodePreview(null)
      setPreviewError(null)
    }
  }, [activeFinding, rawFindings])

  useEffect(() => {
    if (!activeFinding) return

    let stopped = false
    const finding = activeFinding
    async function loadCodePreview() {
      setIsLoadingPreview(true)
      setPreviewError(null)
      setCodePreview(null)

      try {
        const { ok, payload } = await fetchSecretsCodePreview(finding)
        if (stopped) return
        if (!ok || payload.error) {
          setPreviewError(payload.error ?? "Could not load code preview. The file may be unavailable at that commit.")
          return
        }
        setCodePreview(payload)
      } catch (err) {
        if (!stopped) {
          setPreviewError(err instanceof Error ? err.message : "Could not load code preview.")
        }
      } finally {
        if (!stopped) setIsLoadingPreview(false)
      }
    }

    void loadCodePreview()

    return () => {
      stopped = true
    }
  }, [activeFinding])

  const funnel = useMemo(() => {
    let newCount = 0
    let confirmedCount = 0
    let falsePositiveCount = 0
    let actionTakenCount = 0
    for (const finding of filtered) {
      if (finding.reviewStatus === "confirmed") confirmedCount += 1
      else if (finding.reviewStatus === "false_positive") falsePositiveCount += 1
      else if (finding.reviewStatus === "action_taken") actionTakenCount += 1
      else newCount += 1
    }
    const total = Math.max(filtered.length, 1)
    return {
      newCount,
      confirmedCount,
      falsePositiveCount,
      actionTakenCount,
      newPct: Math.round((newCount / total) * 100),
      confirmedPct: Math.round((confirmedCount / total) * 100),
      falsePositivePct: Math.round((falsePositiveCount / total) * 100),
      actionTakenPct: Math.round((actionTakenCount / total) * 100),
    }
  }, [filtered])

  const overviewFunnel = useMemo(() => {
    let newCount = 0
    let confirmedCount = 0
    let falsePositiveCount = 0
    let actionTakenCount = 0
    for (const finding of findings) {
      if (finding.reviewStatus === "confirmed") confirmedCount += 1
      else if (finding.reviewStatus === "false_positive") falsePositiveCount += 1
      else if (finding.reviewStatus === "action_taken") actionTakenCount += 1
      else newCount += 1
    }
    const total = Math.max(findings.length, 1)
    return {
      newCount,
      confirmedCount,
      falsePositiveCount,
      actionTakenCount,
      newPct: Math.round((newCount / total) * 100),
      confirmedPct: Math.round((confirmedCount / total) * 100),
      falsePositivePct: Math.round((falsePositiveCount / total) * 100),
      actionTakenPct: Math.round((actionTakenCount / total) * 100),
    }
  }, [findings])

  const triageQueueFindings = useMemo(
    () => findings.filter((finding) => matchesFindingFilters(finding, filterState, { statusFilter: true })),
    [findings, filterState]
  )
  const triageQueueCounts = useMemo(() => {
    let newCount = 0
    let confirmedCount = 0
    let falsePositiveCount = 0
    let actionTakenCount = 0
    let highRepeatCount = 0
    for (const finding of triageQueueFindings) {
      if (finding.reviewStatus === "confirmed") confirmedCount += 1
      else if (finding.reviewStatus === "false_positive") falsePositiveCount += 1
      else if (finding.reviewStatus === "action_taken") actionTakenCount += 1
      else {
        newCount += 1
        if ((occurrenceCountByKey.get(uniqueFindingKey(finding)) ?? 0) > 1) highRepeatCount += 1
      }
    }
    return { newCount, confirmedCount, falsePositiveCount, actionTakenCount, highRepeatCount }
  }, [triageQueueFindings, occurrenceCountByKey])
  function applyTriageFilter(nextStatus: SecretReviewStatus | "", repeatedOnly = false) {
    setStatusFilter(nextStatus)
    setShowRepeatedOnly(repeatedOnly)
    setSelected(new Set())
  }

  async function applyReview(status: SecretReviewStatus, targetFindings?: SecretFinding[]) {
    const targets =
      targetFindings ?? Array.from(selected).map((key) => findingByRowKey.get(key)).filter((item): item is SecretFinding => Boolean(item))
    if (targets.length === 0) return
    setError(null)

    const byOrg = new Map<string, SecretFinding[]>()
    for (const finding of targets) {
      const next = byOrg.get(finding.organization) ?? []
      next.push(finding)
      byOrg.set(finding.organization, next)
    }

    for (const [org, entries] of byOrg) {
      const updates: ReviewUpdatePayload[] = entries.map((finding) => ({
        fingerprint: finding.fingerprint,
        status,
        secretIdentity: finding.secretIdentity ?? null,
        scope: finding.secretIdentity ? "secret" : "occurrence",
        repository: finding.repository,
        source: finding.source,
        detector: finding.detector,
        filePath: finding.filePath,
        line: finding.line,
        commit: finding.commit,
      }))
      const { ok, payload } = await applySecretsReview(org, updates)
      if (!ok || payload.error) {
        setError(payload.error ?? "Failed to update review status")
        return
      }
    }

    try {
      await Promise.all([loadOverview(), loadGqlFindings(), loadFilterOptions()])
      await loadTabContentRef.current()
    } catch {
      // Best-effort refresh
    }
    setActiveFinding(null)
    setSelected(new Set())
  }

  function toggleSelection(id: string) {
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function setRowSelection(keys: string[], shouldSelect: boolean) {
    setSelected((current) => {
      const next = new Set(current)
      for (const key of keys) {
        if (shouldSelect) next.add(key)
        else next.delete(key)
      }
      return next
    })
  }

  const hasActiveFilters = Boolean(
    organization ||
      repository ||
      source ||
      statusFilter ||
      keyType.length > 0 ||
      ageBucket ||
      newFindings ||
      showRepeatedOnly ||
      search ||
      classificationFilter
  )

  function clearFilters() {
    setSearch("")
    setOrganization("")
    setRepository("")
    setSource("")
    setStatusFilter("")
    setKeyType([])
    setAgeBucket("")
    setNewFindings(false)
    setClassificationFilter([])
    setSortOrder("newest")
    setShowRepeatedOnly(false)
    setSelected(new Set())
    setReviewViewMode("list")
    setFindingsPageNum(1)
  }

  function previewFinding(finding: SecretFinding) {
    setActiveFinding({ ...finding, ...(reviewQueueByFingerprint.get(finding.fingerprint) ?? {}) })
  }

  const statusText =
    latestRun?.status === "queued" ? "Queued"
    : latestRun?.status === "running" ? "Running scan..."
    : latestRun?.status === "ingesting" ? "Ingesting results..."
    : latestRun?.status === "completed" ? "Completed"
    : latestRun?.status === "cancelled" ? "Cancelled"
    : latestRun?.status === "failed" ? "Failed"
    : "Idle"

  useEffect(() => {
    if (!isRunning) return

    const timer = window.setInterval(() => {
      setNowMs(Date.now())
    }, 1000)

    return () => {
      window.clearInterval(timer)
    }
  }, [isRunning])


  return (
    <div className="space-y-5">

      {error && (
        <div className="rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 p-3 text-sm text-red-700 dark:text-red-300">
          {error}
        </div>
      )}

      {!isRunning && latestRun?.reconciled && latestRun.reconciliationReason && (
        <div className="rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 p-3 text-sm text-amber-800 dark:text-amber-200">
          {latestRun.reconciliationReason}
        </div>
      )}



      {showBanner && latestRun && (
        <ScanRunningBanner
          organization={latestRun.organization}
          status={latestRun.status}
          progress={{ ...latestRun.progress, percent: runProgressValue(latestRun), currentClassifying: latestRun.progress?.currentClassifying ?? null }}
          logTail={latestRun.logTail}
          startedAt={latestRun.startedAt ?? null}
          createdAt={latestRun.createdAt ?? null}
          nowMs={nowMs}
          commandLabel={`root@scanner:~$ ./run-secret-scan.sh --org ${latestRun.organization}`}
          scanLabel={`${latestRun.scanDepth === "deep" ? "deep" : latestRun.scanDepth === "ai_enhanced" ? "ai enhanced" : "light"} secret scan`}
          extraStages={{ scanning: "Scanning Repositories" }}
          showSyncLabel={!!latestRun.reconciled}
          progressOverride={(raw, prog, isInit) => {
            const classifying = prog?.currentClassifying ?? null
            if (classifying) {
              const [n, m] = classifying.split("/").map(Number)
              const fraction = m > 0 ? Math.min(1, n / m) : 0
              return 85 + fraction * 14
            }
            if (latestRun.scanDepth === "ai_enhanced") {
              const capped = Math.min(85, raw)
              return isInit ? Math.max(2, capped) : capped
            }
            return isInit ? Math.max(2, raw) : raw
          }}
        />
      )}

      {dashboardDataError && (
        <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-900/20 dark:text-amber-200">
          {dashboardDataError}
        </div>
      )}

      <DashboardTabs tabs={[{ id: "overview", label: "Overview" }, { id: "review", label: "Review" }, { id: "insights", label: "Insights" }, { id: "health", label: "Health" }, { id: "settings", label: "Settings" }] as const} activeTab={activeTab} onChange={setActiveTab} />

      {activeTab === "overview" && (
        <OverviewTab
          uniqueKeyCount={overview?.uniqueKeyCount ?? 0}
          funnel={overview?.reviewFunnel ?? { newCount: 0, confirmedCount: 0, falsePositiveCount: 0, actionTakenCount: 0 }}
          staleCount={overview?.staleFindingsCount ?? 0}
          resolvedRecentlyCount={overview?.resolvedRecentlyCount ?? 0}
          unresolvedCount={overview?.unresolvedCount ?? 0}
          ageBuckets={overview?.ageBuckets ?? []}
          triagePriority={overview?.triagePriority ?? []}
          remediation={overview?.remediation ?? undefined}
          repositoryCoverage={overview?.repositoryCoverage ?? undefined}
          onOpenReviewFiltered={({ status, repo, ageBucket }) => {
            if (status !== undefined) setStatusFilter(status)
            if (repo !== undefined) setRepository(repo)
            if (ageBucket !== undefined) setAgeBucket(ageBucket)
            setActiveTab("review")
            window.scrollTo({ top: 0 })
          }}
        />
      )}

      {activeTab === "review" && (
        <ReviewTab
          sortedRows={sortedRows}
          selected={selected}
          activeFinding={activeFinding}
          codePreview={codePreview}
          correlatedFindings={correlatedFindings}
          isLoadingPreview={isLoadingPreview}
          previewError={previewError}
          search={search}
          organization={organization}
          repository={repository}
          statusFilter={statusFilter}
          keyType={keyType}
          ageBucket={ageBucket}
          newFindings={newFindings}
          sortOrder={sortOrder}
          organizations={organizations}
          repositories={repositories}
          keyTypes={keyTypes}
          hasActiveFilters={hasActiveFilters}
          onSearchChange={setSearch}
          onOrganizationChange={setOrganization}
          onRepositoryChange={setRepository}
          onStatusFilterChange={setStatusFilter}
          onKeyTypeChange={(v) => setKeyType(v ? [v] : [])}
          onAgeBucketChange={setAgeBucket}
          onNewFindingsChange={setNewFindings}
          classificationFilter={classificationFilter}
          onClassificationFilterChange={(v) =>
            setClassificationFilter((prev) =>
              prev.includes(v) ? prev.filter((x) => x !== v) : [...prev, v]
            )
          }
          onClassificationFilterClear={() => setClassificationFilter([])}
          onSortOrderChange={(v) => setSortOrder(v as any)}
          onResetFilters={clearFilters}
          onBulkReview={(status) => void applyReview(status)}
          onPreview={previewFinding}
          onToggleSelect={toggleSelection}
          onSetSelected={setRowSelection}
          canReview={canReview}
          onReview={(status, findings) => {
            void applyReview(status, findings)
          }}
          viewMode={reviewViewMode}
          viewModes={SECRETS_VIEW_MODES}
          onViewModeChange={setReviewViewMode}
          serverPage={findingsPageNum}
          serverPerPage={findingsPerPage}
          serverTotalCount={gqlFindings?.totalCount ?? 0}
          serverTotalPages={gqlFindings?.pageInfo?.totalPages ?? 1}
          onServerPageChange={setFindingsPageNum}
          onServerPerPageChange={(n) => { setFindingsPerPage(n); setFindingsPageNum(1) }}
          onClosePreview={() => {
            setActiveFinding(null)
            setCodePreview(null)
            setPreviewError(null)
          }}
        />
      )}

      {activeTab === "insights" && (
          <InsightsTab
            triagePriority={enrichedTriagePriority}
            trend={insights?.trend ?? []}
            findings={findings}
            availableSources={allSources}
            availableOrganizations={allOrganizations}
            onSelectRepository={(nextRepository) => {
              setRepository(nextRepository)
              setStatusFilter("confirmed")
              setActiveTab("review")
              window.scrollTo({ top: 0 })
            }}
            onSelectKeyType={(detector, status) => {
              setKeyType([detector])
              setStatusFilter(status ?? "")
              setActiveTab("review")
              window.scrollTo({ top: 0 })
            }}
            onSelectCell={(org, detectors) => {
              setOrganization(org)
              setKeyType(detectors)
              setActiveTab("review")
              window.scrollTo({ top: 0 })
            }}
            onSelectAgeBucket={(bucket) => {
              setAgeBucket(bucket)
              setActiveTab("review")
              window.scrollTo({ top: 0 })
            }}
            onFilterChange={(filters) => {
              void refreshInsights(filters)
            }}
          />
      )}

      {activeTab === "health" && (
          <HealthTab
            runHistory={health?.runHistory ?? []}
            coverageGaps={health?.coverageGaps ?? []}
            findings={rawFindings}
          />
      )}

      {activeTab === "settings" && (
        canEdit ? (
          <SecretsContent canEdit={canEdit} />
        ) : (
          <div className="rounded-[28px] border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center">
            <p className="text-sm text-[var(--color-text-secondary)]">You need admin access to manage tool settings.</p>
          </div>
        )
      )}
    </div>
  )
}
