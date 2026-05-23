export interface GqlSeverityCounts {
  total: number
  critical: number
  high: number
  medium: number
  low: number
}

export interface GqlHomeRepoSummary {
  name: string
  open: number
  critical: number
  high: number
}

export interface GqlHomeAgeBucket {
  label: string
  count: number
}

export interface GqlHomeRemediationStats {
  totalFixed: number
  avgDays: number | null
  medianDays: number | null
  fixedLast30d: number
}

export interface GqlHomeAnalytics {
  topRepositories: GqlHomeRepoSummary[]
  ageBuckets: GqlHomeAgeBucket[]
  remediation: GqlHomeRemediationStats
}

export interface GqlPostureTrendPoint {
  date: string
  total: number
  critical: number
  high: number
  medium: number
  low: number
}

export interface GqlDependenciesFinding {
  id: string
  state: string
  severity: string
  ecosystem: string
  packageName: string
  vulnerableVersion: string
  patchedVersion: string | null
  repoFullName: string
  advisorySummary: string | null
  cvssScore: number | null
  firstSeenAt: string | null
  fixedAt: string | null
  currentVersion: string | null
  manifestPath: string | null
}


export interface GqlPageInfo {
  hasNextPage: boolean
  hasPreviousPage: boolean
  totalPages: number
}

export interface GqlDependenciesFindingsConnection {
  items: GqlDependenciesFinding[]
  totalCount: number
  pageInfo: GqlPageInfo
}


export interface GqlSeverityBucket {
  severity: string
  count: number
  percentage: number
}

export interface GqlAgeBucket {
  label: string
  count: number
}

export interface GqlRepoSummary {
  name: string
  open: number
  critical: number
  high: number
}

export interface GqlRemediationStats {
  totalFixed: number
  avgDays: number | null
  medianDays: number | null
  fixedLast30d: number
}

export interface GqlCoverageStats {
  total: number
  affected: number
  unaffected: number
  percentage: number
}

export interface GqlRiskScore {
  score: number
  rating: string
  summary: string
}

export interface GqlFilterOptions {
  ecosystems: string[]
  repositories: string[]
  organizations: string[]
}

export interface GqlMonthlyTrendItem {
  month: string
  introduced: number
  resolved: number
  openAtEnd: number
}

export interface GqlEcosystemBreakdownItem {
  ecosystem: string
  critical: number
  high: number
  medium: number
  low: number
  total: number
}

export interface GqlVulnerablePackage {
  name: string
  ecosystem: string
  repoCount: number
  critical: number
  high: number
  medium: number
  low: number
}

export interface GqlMTTRBySeverity {
  critical: number | null
  high: number | null
  medium: number | null
  low: number | null
}

export interface GqlRemediationPriorityRow {
  rank: number
  packageName: string
  ecosystem: string
  ghsaId: string
  cveId: string | null
  severity: string
  reposAffected: number
  patchVersion: string | null
  advisoryUrl: string
}

export interface GqlDependenciesAnalytics {
  counts: GqlSeverityCounts
  severityDistribution: GqlSeverityBucket[]
  ageBuckets: GqlAgeBucket[]
  topRepositories: GqlRepoSummary[]
  remediation: GqlRemediationStats
  repositoryCoverage: GqlCoverageStats
  riskScore: GqlRiskScore
  staleFindingsCount: number
  deferredFindingsCount: number
  monthlyTrend: GqlMonthlyTrendItem[]
  ecosystemBreakdown: GqlEcosystemBreakdownItem[]
  topVulnerablePackages: GqlVulnerablePackage[]
  mttrBySeverity: GqlMTTRBySeverity
  remediationPriority: GqlRemediationPriorityRow[]
}



// Code Scanning types
export interface GqlCodeScanningAiReview {
  verdict: string
  explanation: string
  reasoning?: string | null
  confidence?: string | null
}

export interface GqlCodeScanningCodeFlow {
  file: string
  line: number
  snippet: string
}

export interface GqlCodeScanningCallChainStep {
  function: string
  file: string
  line: number
}

export interface GqlCodeScanningReachability {
  verdict: string
  entryPoint?: string | null
  callChain?: GqlCodeScanningCallChainStep[] | null
}

export interface GqlCodeScanningFinding {
  id: string
  state: string
  severity: string
  ruleId: string
  ruleName: string
  message: string
  filePath: string
  line: number
  repoFullName: string
  firstSeenAt: string | null
  fixedAt: string | null
  language: string | null
  confidence: string | null
  category?: string | null
  cwe?: string[] | null
  snippet?: string | null
  fixSuggestion?: string | null
  codeWindow?: string | null
  aiReview?: GqlCodeScanningAiReview | null
  codeFlows?: GqlCodeScanningCodeFlow[] | null
  reachability?: GqlCodeScanningReachability | null
}

export interface GqlCodeScanningFindingsConnection {
  items: GqlCodeScanningFinding[]
  totalCount: number
  pageInfo: GqlPageInfo
}

export interface GqlCodeScanningRuleCount {
  ruleId: string
  ruleName: string
  count: number
}

export interface GqlStateBreakdown {
  open: number
  dismissed: number
  fixed: number
  awaitingFix: number
}

export interface GqlCategoryCount {
  category: string
  count: number
}

export interface GqlCodeScanningFilterOptions {
  repositories: string[]
  languages: string[]
  ruleIds: string[]
}

export interface GqlCodeScanningAnalytics {
  counts: GqlSeverityCounts
  severityDistribution: GqlSeverityBucket[]
  ageBuckets: GqlAgeBucket[]
  topRepositories: GqlRepoSummary[]
  remediation: GqlRemediationStats
  repositoryCoverage: GqlCoverageStats
  riskScore: GqlRiskScore
  topRules: GqlCodeScanningRuleCount[]
  awaitingFixCount: number
  stateBreakdown: GqlStateBreakdown
  categoryBreakdown: GqlCategoryCount[]
}

// Container types
export interface GqlContainerFinding {
  id: string
  state: string
  severity: string
  ecosystem: string
  packageName: string
  vulnerableVersion: string
  patchedVersion: string | null
  repoFullName: string
  advisorySummary: string | null
  cvssScore: number | null
  firstSeenAt: string | null
  fixedAt: string | null
  currentVersion: string | null
  manifestPath: string | null
}

export interface GqlContainerFindingsConnection {
  items: GqlContainerFinding[]
  totalCount: number
  pageInfo: GqlPageInfo
}

export interface GqlContainerAnalytics {
  counts: GqlSeverityCounts
  severityDistribution: GqlSeverityBucket[]
  ageBuckets: GqlAgeBucket[]
  topRepositories: GqlRepoSummary[]
  remediation: GqlRemediationStats
  repositoryCoverage: GqlCoverageStats
  riskScore: GqlRiskScore
  staleFindingsCount: number
  deferredFindingsCount: number
  monthlyTrend: GqlMonthlyTrendItem[]
  ecosystemBreakdown: GqlEcosystemBreakdownItem[]
  topVulnerablePackages: GqlVulnerablePackage[]
  mttrBySeverity: GqlMTTRBySeverity
  remediationPriority: GqlRemediationPriorityRow[]
}

// Secrets types
export interface GqlClassificationEntry {
  value: string
  source: string
  scanDepth: string | null
  confidence: number | null
  runId: string | null
  scannedAt: string | null
}

export interface GqlSecretFinding {
  id: string
  state: string
  reviewStatus: string
  detector: string
  filePath: string
  line: number | null
  repository: string
  organization: string
  commit: string | null
  secretSnippet: string | null
  firstSeenAt: string | null
  dismissedAt: string | null
  dismissedBy: string | null
  dismissedReason: string | null
  secretIdentity: string | null
  fingerprint: string | null
  source: string
  classificationHistory: GqlClassificationEntry[]
  riskScore: number | null
  occurrenceCount: number | null
  confirmedAt: string | null
  resolvedAt: string | null
  detectedAt: string | null
}

export interface GqlSecretFindingsConnection {
  items: GqlSecretFinding[]
  totalCount: number
  pageInfo: GqlPageInfo
}

export interface GqlReviewFunnel {
  newCount: number
  confirmedCount: number
  falsePositiveCount: number
  actionTakenCount: number
}

export interface GqlSourceCount {
  source: string
  count: number
}

export interface GqlSecretsRepoPriority {
  organization: string
  repository: string
  unreviewedCount: number
  confirmedCount: number
}

export interface GqlSecretsOverview {
  uniqueKeyCount: number
  totalFindingsCount: number
  reviewFunnel: GqlReviewFunnel
  sourceBreakdown: GqlSourceCount[]
  remediation: GqlRemediationStats
  repositoryCoverage: GqlCoverageStats
  staleFindingsCount: number
  resolvedRecentlyCount: number
  unresolvedCount: number
  ageBuckets: GqlAgeBucket[]
  triagePriority: GqlSecretsRepoPriority[]
}

export interface GqlSecretsFilterOptions {
  organizations: string[]
  repositories: string[]
  detectors: string[]
  sources: string[]
}
