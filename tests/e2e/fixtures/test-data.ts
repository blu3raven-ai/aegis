/** Synthetic test data constants for mocked e2e tests. */

export const TEST_ORG = "acme-corp"

export const TEST_REPOS = [
  "acme-corp/web-app",
  "acme-corp/api-server",
  "acme-corp/auth-service",
] as const

export const MOCK_SECRET_FINDING = {
  id: "si-e2e-001",
  state: "open",
  reviewStatus: "new",
  detector: "generic-api-key",
  filePath: "src/config.py",
  line: 42,
  repository: "web-app",
  organization: TEST_ORG,
  commit: "abc1234",
  secretSnippet: "AKIAIOSFODNN7EXAMPLE",
  firstSeenAt: "2026-04-01T00:00:00Z",
  dismissedAt: null,
  dismissedBy: null,
  dismissedReason: null,
  secretIdentity: "si-e2e-001",
  fingerprint: "fp-e2e-001",
  source: "github",
  classificationHistory: [
    { value: "likely_real", source: "scanner", scanDepth: "light", confidence: 0.85, runId: "run-1", scannedAt: "2026-04-01T00:00:00Z" },
  ],
  riskScore: 7.5,
  occurrenceCount: 3,
  confirmedAt: null,
  resolvedAt: null,
  detectedAt: "2026-04-01T00:00:00Z",
}

export function makeSecretFindings(count: number) {
  return Array.from({ length: count }, (_, i) => ({
    ...MOCK_SECRET_FINDING,
    id: `si-e2e-${String(i + 1).padStart(3, "0")}`,
    secretIdentity: `si-e2e-${String(i + 1).padStart(3, "0")}`,
    fingerprint: `fp-e2e-${String(i + 1).padStart(3, "0")}`,
    reviewStatus: ["new", "confirmed", "false_positive", "action_taken"][i % 4],
    detector: ["generic-api-key", "aws-access-key", "github-pat"][i % 3],
    repository: TEST_REPOS[i % 3].split("/")[1],
  }))
}

export const DEFAULT_SECRETS_OVERVIEW = {
  uniqueKeyCount: 15,
  totalFindingsCount: 20,
  reviewFunnel: { newCount: 8, confirmedCount: 5, falsePositiveCount: 4, actionTakenCount: 3 },
  sourceBreakdown: [{ source: "github", count: 20 }],
}

export const DEFAULT_SECRET_FINDINGS_CONNECTION = {
  items: makeSecretFindings(10),
  totalCount: 20,
  pageInfo: { hasNextPage: true, hasPreviousPage: false, totalPages: 2 },
}

export const DEFAULT_SECRET_FILTER_OPTIONS = {
  organizations: [TEST_ORG],
  repositories: TEST_REPOS.map((r) => r.split("/")[1]),
  detectors: ["generic-api-key", "aws-access-key", "github-pat"],
  sources: ["github"],
}

export const DEFAULT_SEVERITY_COUNTS = {
  total: 13,
  critical: 5,
  high: 8,
  medium: 0,
  low: 0,
}

export const MOCK_DEPENDENCIES_FINDING = {
  id: "dep-e2e-001",
  state: "open",
  severity: "high",
  ecosystem: "npm",
  packageName: "lodash",
  vulnerableVersion: "<4.17.21",
  patchedVersion: "4.17.21",
  repoFullName: "acme-corp/web-app",
  advisorySummary: "Prototype Pollution in lodash",
  cvssScore: 7.5,
  firstSeenAt: "2026-03-15T00:00:00Z",
  fixedAt: null,
}

export const MOCK_CODE_SCANNING_FINDING = {
  id: "code-e2e-001",
  state: "open",
  severity: "high",
  ruleId: "javascript.lang.security.detect-eval-with-expression",
  ruleName: "Eval with expression",
  message: "Detected eval() with a non-literal argument",
  filePath: "src/utils/parser.js",
  line: 15,
  repoFullName: "acme-corp/web-app",
  firstSeenAt: "2026-03-10T00:00:00Z",
  fixedAt: null,
  language: "javascript",
  confidence: "high",
}
