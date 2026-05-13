import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync, existsSync } from "node:fs"
import { fileURLToPath } from "node:url"

test("findings-toolbar.tsx has been deleted", () => {
  const filePath = fileURLToPath(new URL("./findings-toolbar.tsx", import.meta.url))
  assert.ok(!existsSync(filePath), "findings-toolbar.tsx should no longer exist")
})

test("secrets dashboard view uses tabbed layout with persistent run progress banner", () => {
  const source = readFileSync(new URL("./SecretsDashboardView.tsx", import.meta.url), "utf8")

  assert.match(source, /DashboardTabs/)
  assert.match(source, /activeTab/)
  assert.match(source, /"overview"/)
  assert.match(source, /"review"/)
  assert.match(source, /"insights"/)
  assert.match(source, /"health"/)

  const runProgressIndex = source.indexOf("<ScanRunningBanner")
  const tabsIndex = source.indexOf("<DashboardTabs")
  assert.ok(runProgressIndex >= 0, "expected ScanRunningBanner render")
  assert.ok(tabsIndex >= 0, "expected DashboardTabs render")
  assert.ok(runProgressIndex < tabsIndex, "scan running banner should render above dashboard tabs")
})

test("page shell uses SSE instead of polling for scan updates", () => {
  const source = readFileSync(new URL("../dashboard/SecretsPageShell.tsx", import.meta.url), "utf8")

  assert.match(source, /useSSE/, "expected useSSE hook usage")
  assert.doesNotMatch(source, /setInterval/, "should not use setInterval polling")
})

test("secrets api paths and client expose review queue, insights, and health fetchers", () => {
  const apiPaths = readFileSync(new URL("../../lib/api-paths.ts", import.meta.url), "utf8")
  const dashboardClient = readFileSync(new URL("../../lib/secrets/dashboard-client.ts", import.meta.url), "utf8")

  assert.match(apiPaths, /reviewQueue:\s*"\/api\/secrets\/review-queue"/)
  assert.match(apiPaths, /insights:\s*"\/api\/secrets\/insights"/)
  assert.match(apiPaths, /health:\s*"\/api\/secrets\/health"/)

  assert.match(dashboardClient, /fetchSecretsReviewQueue/)
  assert.match(dashboardClient, /fetchSecretsInsights/)
  assert.match(dashboardClient, /fetchSecretsHealth/)
})

test("code preview panel renders review context signals", () => {
  const source = readFileSync(new URL("./code-preview-panel.tsx", import.meta.url), "utf8")

  assert.match(source, /repoHistorySignal/)
  assert.match(source, /detectorNoiseRate/)
  assert.match(source, /secretAgeDays/)
})

test("dashboard-utils FindingFilterState includes keyType field", () => {
  const source = readFileSync(new URL("../../lib/secrets/dashboard-utils.ts", import.meta.url), "utf8")
  assert.match(source, /keyType:\s*string/)
  assert.match(source, /matchesKeyType/)
})

test("ReviewSearchBar renders full-width search input and all five filter controls", () => {
  const source = readFileSync(new URL("./review-search-bar.tsx", import.meta.url), "utf8")

  assert.match(source, /"use client"/)
  assert.match(source, /Search by repo, detector, snippet, file path/)
  assert.match(source, /statusFilter/)
  assert.match(source, /keyType/)
  assert.match(source, /sortOrder/)
  assert.match(source, /Newest first/)
  assert.match(source, /Oldest first/)
  assert.match(source, /Most occurrences/)
  assert.match(source, /Highest risk score/)
  assert.match(source, /onBulkReview/)
})

test("SecretsDashboardView tracks keyType and sortOrder state", () => {
  const source = readFileSync(new URL("./SecretsDashboardView.tsx", import.meta.url), "utf8")

  assert.match(source, /keyType/)
  assert.match(source, /setKeyType/)
  assert.match(source, /sortOrder/)
  assert.match(source, /setSortOrder/)
  assert.match(source, /keyTypes/)
  // Priority Queue props no longer forwarded to ReviewTab
  assert.doesNotMatch(source, /<ReviewTab[^>]*reviewQueue=\{reviewQueue\}/)
  assert.doesNotMatch(source, /<ReviewTab[^>]*queueLoading=/)
  assert.doesNotMatch(source, /<ReviewTab[^>]*queueError=/)
})

test("ReviewTab uses ReviewSearchBar and has no Priority Queue block", () => {
  const source = readFileSync(new URL("./review-tab.tsx", import.meta.url), "utf8")

  assert.match(source, /ReviewSearchBar/)
  assert.doesNotMatch(source, /FindingsToolbar/)
  assert.doesNotMatch(source, /Priority Queue/)
  assert.doesNotMatch(source, /Pre-sorted findings for review/)
  assert.doesNotMatch(source, /reviewQueue/)
  assert.doesNotMatch(source, /queueLoading/)
  // Drawer: CodePreviewPanel rendered outside the table container
  assert.match(source, /fixed.*inset-0.*backdrop|inset-0.*fixed.*backdrop|mobile.*backdrop|backdrop.*mobile/i)
})

test("CodePreviewPanel uses fixed overlay positioning with slide-in transition", () => {
  const source = readFileSync(new URL("./code-preview-panel.tsx", import.meta.url), "utf8")

  assert.match(source, /"use client"/)
  assert.match(source, /fixed/)
  assert.match(source, /translate-x-full/)
  assert.match(source, /translate-x-0/)
  assert.match(source, /useEffect/)
  assert.match(source, /Escape/)
  // GitHub link always in header, not only in error body
  assert.match(source, /Open in GitHub/)
})

test("RepoGroupedFindings has no Preview badge and uses simplified active highlight", () => {
  const source = readFileSync(new URL("./repo-grouped-findings.tsx", import.meta.url), "utf8")

  assert.doesNotMatch(source, /Preview/)
  assert.match(source, /bg-orange-500\/5/)
})

test("insights tab renders the three-section narrative layout", () => {
  const source = readFileSync(new URL("./insights-tab.tsx", import.meta.url), "utf8")

  assert.match(source, /Safety Trend/)
  assert.match(source, /Risk Concentration/)
  assert.match(source, /Action Priorities/)
  assert.match(source, /BacklogHealthChart/)
  assert.match(source, /BacklogChangeWaterfallChart/)
  assert.match(source, /SecretsKpiStrip/)
  assert.match(source, /OrgSecretHeatmap/)
  assert.match(source, /OrgAgeBucketsChart/)
  assert.match(source, /SecretTypeChart/)
  assert.match(source, /RepoRiskScatterChart/)
  assert.match(source, /TriageFunnelChart/)
})

test("safety trend uses compact header, inline filters, and a 2-column chart row", () => {
  const source = readFileSync(new URL("./insights-tab.tsx", import.meta.url), "utf8")

  assert.match(source, /Safety Trend/)
  assert.match(source, /Are we reducing open exposure faster than new secrets are being found\?/)
  assert.match(source, /availableSources/)
  assert.match(source, /availableOrganizations/)
  assert.match(source, /border-t border-\[var\(--color-border\)\] pt-12/)
  assert.doesNotMatch(source, /rounded-3xl border border-\[var\(--color-border\)\] bg-\[var\(--color-surface-raised\)\] p-5 lg:flex-row/)
  assert.match(source, /lg:grid-cols-\[minmax\(0,1\.35fr\)_minmax\(320px,0\.9fr\)\]/)
})

test("safety trend uses denser KPI cards and a narrative change-drivers panel", () => {
  const kpis = readFileSync(new URL("./secrets-kpi-strip.tsx", import.meta.url), "utf8")
  const waterfall = readFileSync(new URL("./backlog-change-waterfall-chart.tsx", import.meta.url), "utf8")

  assert.match(kpis, /md:grid-cols-3/)
  assert.match(kpis, /rounded-2xl|rounded-3xl/)
  assert.match(waterfall, /What changed this period/)
  assert.match(waterfall, /Increased backlog|Reduced backlog|Ending backlog/)
})

test("backlog health chart emphasizes the latest point and uses fuller vertical space", () => {
  const source = readFileSync(new URL("./backlog-health-chart.tsx", import.meta.url), "utf8")

  assert.match(source, /latest/i)
  assert.match(source, /circle/)
  assert.match(source, /Unresolved exposure/)
})

test("secrets dashboard view passes findings and insights data into the redesigned insights tab", () => {
  const source = readFileSync(new URL("./SecretsDashboardView.tsx", import.meta.url), "utf8")

  assert.match(source, /triagePriority=\{.*triagePriority.*\}/)
  assert.match(source, /trend=\{insights\?\.trend \?\? \[\]\}/)
  assert.match(source, /findings=\{findings\}/)
  assert.match(source, /availableSources=\{allSources\}/)
  assert.match(source, /availableOrganizations=\{allOrganizations\}/)
  assert.match(source, /fetchSecretsInsights\(orgQuery,\s*filters\)/)
  assert.match(source, /setActiveTab\("review"\)/)
  assert.match(source, /setStatusFilter\("confirmed"\)/)
})

test("section 1 uses backlog line, waterfall, and KPI strip", () => {
  const backlogHealth = readFileSync(new URL("./backlog-health-chart.tsx", import.meta.url), "utf8")
  const waterfall = readFileSync(new URL("./backlog-change-waterfall-chart.tsx", import.meta.url), "utf8")
  const kpis = readFileSync(new URL("./secrets-kpi-strip.tsx", import.meta.url), "utf8")

  assert.match(backlogHealth, /HEIGHT\s*=\s*320/)
  assert.match(backlogHealth, /trend\.at\(-1\)/)
  assert.match(backlogHealth, /Latest exposure|Latest month/)
  assert.match(backlogHealth, /latestPoint/)

  assert.match(waterfall, /BacklogChangeWaterfallChart/)
  assert.match(waterfall, /starting backlog/i)
  assert.match(waterfall, /ending backlog/i)

  assert.match(kpis, /Current unresolved exposure/)
  assert.match(kpis, /Net backlog change this period/)
  assert.match(kpis, /Median age of unresolved confirmed findings/)
})

test("section 2 uses heatmap, org age buckets, and secret type concentration", () => {
  const heatmap = readFileSync(new URL("./org-secret-heatmap.tsx", import.meta.url), "utf8")
  const ageChart = readFileSync(new URL("./org-age-buckets-chart.tsx", import.meta.url), "utf8")
  const insights = readFileSync(new URL("./insights-tab.tsx", import.meta.url), "utf8")

  assert.match(heatmap, /OrgSecretHeatmap/)
  assert.match(ageChart, /OrgAgeBucketsChart/)
  assert.match(insights, /Risk Concentration/)
  assert.match(insights, /SecretTypeChart/)
})

test("section 3 uses repo scatter, triage funnel, and triage list", () => {
  const scatter = readFileSync(new URL("./repo-risk-scatter-chart.tsx", import.meta.url), "utf8")
  const funnel = readFileSync(new URL("./triage-funnel-chart.tsx", import.meta.url), "utf8")
  const insights = readFileSync(new URL("./insights-tab.tsx", import.meta.url), "utf8")

  assert.match(scatter, /RepoRiskScatterChart/)
  assert.match(funnel, /TriageFunnelChart/)
  assert.match(insights, /Action Priorities/)
})

test("ToolSettingsForm supports checkbox password and optional fields", () => {
  const source = readFileSync(new URL("../../app/(app)/settings/ToolSettingsForm.tsx", import.meta.url), "utf8")

  assert.match(source, /type:\s*"number"\s*\|\s*"text"\s*\|\s*"password"\s*\|\s*"checkbox"/)
  assert.match(source, /required\?:\s*boolean/)
  assert.match(source, /field\.type === "checkbox"/)
  assert.match(source, /checked=\{values\[field\.key\] === "true"\}/)
})

test("Secrets settings exposes AI review assistant controls", () => {
  const source = readFileSync(new URL("../../app/(app)/settings/secrets/SecretsContent.tsx", import.meta.url), "utf8")

  assert.match(source, /AI review assistant/)
  assert.match(source, /aiReviewEnabled/)
  assert.match(source, /aiApiKey/)
  assert.match(source, /may send limited code context/)
})

test("secrets AI assessment client and proxy are wired", () => {
  const apiPaths = readFileSync(new URL("../../lib/api-paths.ts", import.meta.url), "utf8")
  const dashboardClient = readFileSync(new URL("../../lib/secrets/dashboard-client.ts", import.meta.url), "utf8")
  const proxy = readFileSync(new URL("../../app/api/secrets/[...path]/route.ts", import.meta.url), "utf8")
  const types = readFileSync(new URL("../../lib/secrets/types.ts", import.meta.url), "utf8")

  assert.match(apiPaths, /aiAssessment:\s*"\/api\/secrets\/ai-assessment"/)
  assert.match(dashboardClient, /fetchSecretsAiConfig/)
  assert.match(dashboardClient, /requestSecretsAiAssessment/)
  assert.match(proxy, /export async function POST/)
  assert.match(types, /SecretAiAssessmentResult/)
})

test("CodePreviewPanel renders AI assessment before key verdict", () => {
  const source = readFileSync(new URL("./code-preview-panel.tsx", import.meta.url), "utf8")

  assert.match(source, /SecretAiAssessmentPanel/)
  const aiIndex = source.indexOf("<SecretAiAssessmentPanel")
  const verdictIndex = source.indexOf("Key verdict")
  assert.ok(aiIndex >= 0, "expected AI assessment panel")
  assert.ok(verdictIndex >= 0, "expected Key verdict section")
  assert.ok(aiIndex < verdictIndex, "AI assessment should render before Key verdict")
})

test("SecretAiAssessmentPanel includes configure loading success error and advisory states", () => {
  const source = readFileSync(new URL("./secret-ai-assessment-panel.tsx", import.meta.url), "utf8")

  assert.match(source, /AI assessment/)
  assert.match(source, /Analyze with AI/)
  assert.match(source, /Analyzing code context/)
  assert.match(source, /Likely real/)
  assert.match(source, /Likely false positive/)
  assert.match(source, /Use this as a second opinion/)
  assert.match(source, /AI may be wrong/)
  assert.match(source, /Retry/)
})

test("AI assessment does not call review mutation from drawer UI", () => {
  const source = readFileSync(new URL("./secret-ai-assessment-panel.tsx", import.meta.url), "utf8")

  assert.doesNotMatch(source, /applySecretsReview/)
  assert.doesNotMatch(source, /onReview/)
})

test("SecretsPageShell refresh dropdown has AI Enhanced Scan option", () => {
  const source = readFileSync(
    new URL("../../app/(app)/secrets/dashboard/SecretsPageShell.tsx", import.meta.url),
    "utf8"
  )
  assert.match(source, /ai_enhanced/)
  assert.match(source, /AI Enhanced Scan/)
  assert.match(source, /AI classifier/)
})

test("RepoGroupedFindings renders verifiedStatus badge for trufflehog findings", () => {
  const source = readFileSync(new URL("./repo-grouped-findings.tsx", import.meta.url), "utf8")
  assert.match(source, /verifiedStatus/)
  assert.match(source, /Verified/)
  assert.match(source, /Unverified/)
  assert.match(source, /emerald/)
})

test("RepoGroupedFindings renders aiClassification badge for ai_enhanced findings", () => {
  const source = readFileSync(new URL("./repo-grouped-findings.tsx", import.meta.url), "utf8")
  assert.match(source, /aiClassification/)
  assert.match(source, /Likely Real/)
  assert.match(source, /Likely FP/)
  assert.match(source, /Uncertain/)
})
