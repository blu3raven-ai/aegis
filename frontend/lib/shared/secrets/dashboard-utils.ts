import type { ClassificationEntry, SecretFinding, SecretReviewStatus, SecretScanRun } from "@/lib/shared/secrets/types"

// ---------------------------------------------------------------------------
// Detector categorisation
// ---------------------------------------------------------------------------
// Built from the actual detector/rule-id namespaces of TruffleHog.
// Strategy:
//   1. Normalise the detector name to lowercase, strip separators → plain token list
//   2. Match the first token (vendor prefix) against VENDOR_MAP
//   3. Fall back to TYPE_PATTERNS (credential-type keywords anywhere in the name)
//   4. Default → "Other"
//
// To add a new tool's detectors: add its vendor prefix to VENDOR_MAP (one line).
// To add a new credential type: add a regex to TYPE_PATTERNS (one line).

/** Maps the first dash/underscore-separated token of a detector name → category. */
const VENDOR_MAP: Record<string, string> = {
  // ── Cloud infrastructure ──────────────────────────────────────────────────
  aws:           "Cloud",
  azure:         "Cloud",
  gcp:           "Cloud",
  google:        "Cloud",
  digitalocean:  "Cloud",
  cloudflare:    "Cloud",
  heroku:        "Cloud",
  flyio:         "Cloud",
  fly:           "Cloud",
  linode:        "Cloud",
  scaleway:      "Cloud",
  vultr:         "Cloud",
  oracle:        "Cloud",
  ibm:           "Cloud",
  alibaba:       "Cloud",
  scalingo:      "Cloud",
  render:        "Cloud",
  railway:       "Cloud",

  // ── Hosting / CDN / serverless ────────────────────────────────────────────
  vercel:        "Cloud",
  netlify:       "Cloud",
  fastly:        "Cloud",
  cloudsmith:    "Cloud",

  // ── AI / ML ───────────────────────────────────────────────────────────────
  openai:        "AI/ML",
  anthropic:     "AI/ML",
  huggingface:   "AI/ML",
  deepseek:      "AI/ML",
  groq:          "AI/ML",
  mistral:       "AI/ML",
  xai:           "AI/ML",
  cerebras:      "AI/ML",
  nvapi:         "AI/ML",
  nvidia:        "AI/ML",
  elevenlabs:    "AI/ML",
  replicate:     "AI/ML",
  stability:     "AI/ML",
  cohere:        "AI/ML",
  perplexity:    "AI/ML",
  togetherai:    "AI/ML",
  langfuse:      "AI/ML",
  langsmith:     "AI/ML",
  deepai:        "AI/ML",
  deepgram:      "AI/ML",
  assemblyai:    "AI/ML",
  gemini:        "AI/ML",
  googlegemini:  "AI/ML",
  moonshot:      "AI/ML",
  openaiadmin:   "AI/ML",
  azure_openai:  "AI/ML",
  greptile:      "AI/ML",
  saladcloud:    "AI/ML",
  ngc:           "AI/ML",  // NVIDIA GPU Cloud
  weightsandbiases: "AI/ML",

  // ── Version control ───────────────────────────────────────────────────────
  github:        "VCS",
  gitlab:        "VCS",
  bitbucket:     "VCS",
  gitea:         "VCS",
  sourcegraph:   "VCS",
  sourcegraphcody: "VCS",

  // ── CI/CD ─────────────────────────────────────────────────────────────────
  travisci:      "CI/CD",
  circleci:      "CI/CD",
  buildkite:     "CI/CD",
  droneci:       "CI/CD",
  semaphore:     "CI/CD",
  codemagic:     "CI/CD",
  codeclimate:   "CI/CD",
  codecov:       "CI/CD",
  harness:       "CI/CD",
  prefect:       "CI/CD",

  // ── Payment ───────────────────────────────────────────────────────────────
  stripe:        "Payment",
  paypal:        "Payment",
  paypaloauth:   "Payment",
  square:        "Payment",
  squareapp:     "Payment",
  braintree:     "Payment",
  razorpay:      "Payment",
  flutterwave:   "Payment",
  plaid:         "Payment",
  paystack:      "Payment",
  paymongo:      "Payment",
  wepay:         "Payment",
  dwolla:        "Payment",
  rechargepayments: "Payment",
  lob:           "Payment",
  taxjar:        "Payment",

  // ── Messaging / Email ─────────────────────────────────────────────────────
  slack:         "Messaging",
  discord:       "Messaging",
  telegram:      "Messaging",
  twilio:        "Messaging",
  twilioapikey:  "Messaging",
  messagebird:   "Messaging",
  sendgrid:      "Messaging",
  mailgun:       "Messaging",
  mailchimp:     "Messaging",
  mailerlite:    "Messaging",
  mailjet:       "Messaging",
  mailjetbasicauth: "Messaging",
  mailjetsms:    "Messaging",
  mandrill:      "Messaging",
  postmark:      "Messaging",
  sendinblue:    "Messaging",
  sparkpost:     "Messaging",
  sinch:         "Messaging",
  sinchmessage:  "Messaging",
  telnyx:        "Messaging",
  signalwire:    "Messaging",
  plivo:         "Messaging",
  nexmo:         "Messaging",
  nexmoapikey:   "Messaging",
  vonage:        "Messaging",
  bulksms:       "Messaging",
  textmagic:     "Messaging",
  microsoftteams: "Messaging",
  zapier:        "Messaging",
  tineswebhook:  "Messaging",

  // ── Monitoring / Observability ────────────────────────────────────────────
  datadog:       "Monitoring",
  newrelic:      "Monitoring",
  grafana:       "Monitoring",
  splunk:        "Monitoring",
  sentry:        "Monitoring",
  honeycomb:     "Monitoring",
  loggly:        "Monitoring",
  logzio:        "Monitoring",
  sumologic:     "Monitoring",
  rollbar:       "Monitoring",
  raygun:        "Monitoring",
  bugsnag:       "Monitoring",
  airbrake:      "Monitoring",
  airbrakeprojectkey: "Monitoring",
  airbrakeuserkey: "Monitoring",
  statuspage:    "Monitoring",
  statuscake:    "Monitoring",
  uptimerobot:   "Monitoring",
  opsgenie:      "Monitoring",
  pagerduty:     "Monitoring",
  pagerdutyapikey: "Monitoring",

  // ── Database / Data ───────────────────────────────────────────────────────
  postgres:      "Database",
  mongodb:       "Database",
  redis:         "Database",
  snowflake:     "Database",
  databricks:    "Database",
  databrickstoken: "Database",
  planetscale:   "Database",
  couchbase:     "Database",
  sqlserver:     "Database",
  jdbc:          "Database",
  mysql:         "Database",
  elasticsearch: "Database",
  clickhouse:    "Database",
  supabase:      "Database",
  neon:          "Database",
  aiven:         "Database",
  yugabyte:      "Database",

  // ── Secrets / Infra / Auth ────────────────────────────────────────────────
  hashicorp:     "Secrets Mgmt",
  vault:         "Secrets Mgmt",
  doppler:       "Secrets Mgmt",
  infracost:     "Secrets Mgmt",
  pulumi:        "Secrets Mgmt",
  terraform:     "Secrets Mgmt",
  terraformcloud: "Secrets Mgmt",
  onepassword:   "Secrets Mgmt",
  kubernetes:    "Secrets Mgmt",
  okta:          "Identity",
  auth0:         "Identity",
  auth0managementapitoken: "Identity",
  auth0oauth:    "Identity",
  onelogin:      "Identity",
  jumpcloud:     "Identity",
  ldap:          "Identity",
  defined:       "Identity",
  authress:      "Identity",
}

/** Fallback: match anywhere in the detector name by credential-type keyword. */
const TYPE_PATTERNS: Array<[RegExp, string]> = [
  [/private[-_]?key|rsa|pkcs|pem/i,       "Private Key"],
  [/jwt/i,                                 "Token"],
  [/oauth/i,                               "Token"],
  [/personal[-_]?access[-_]?token/i,       "Token"],
  [/bearer/i,                              "Token"],
  [/token/i,                               "Token"],
  [/api[-_]?key/i,                         "API Key"],
  [/access[-_]?key/i,                      "API Key"],
  [/webhook/i,                             "Webhook"],
  [/password|passwd/i,                     "Password"],
  [/database|db|jdbc/i,                    "Database"],
  [/secret/i,                              "API Key"],
  [/cert(ificate)?/i,                      "Certificate"],
]

export function secretCategory(detector: string): string {
  // Normalise: lowercase, collapse separators, take first segment as vendor
  const lower = detector.toLowerCase().replace(/[^a-z0-9]/g, "")
  const vendor = detector.toLowerCase().split(/[-_]/)[0]

  // 1. Exact vendor prefix lookup
  if (vendor in VENDOR_MAP) return VENDOR_MAP[vendor]

  // 2. Some detectors (e.g. azure_openai, gcpapplicationdefaultcredentials) have
  //    a compound prefix — try the normalised full name against VENDOR_MAP too.
  for (const [key, cat] of Object.entries(VENDOR_MAP)) {
    if (lower.startsWith(key.replace(/[^a-z0-9]/g, ""))) return cat
  }

  // 3. Type-keyword fallback
  for (const [pattern, category] of TYPE_PATTERNS) {
    if (pattern.test(detector)) return category
  }

  return "Other"
}

export interface FindingFilterState {
  organization: string
  repository: string
  source: string
  keyType: string[]
  statusFilter: string
  ageBucket: string
  newFindings?: boolean
  lastScanDate?: string | null
  search: string
  nowMs: number
  classificationFilter: string[]
}

// ---------------------------------------------------------------------------
// Age bucket definitions (shared between chart and filter)
// ---------------------------------------------------------------------------
export const AGE_BUCKETS = [
  { label: "< 7d",  minDays: 0,   maxDays: 7   },
  { label: "7–30d", minDays: 7,   maxDays: 30  },
  { label: "1–3mo", minDays: 30,  maxDays: 90  },
  { label: "3–6mo", minDays: 90,  maxDays: 180 },
  { label: "6mo+",  minDays: 180, maxDays: Number.POSITIVE_INFINITY },
] as const

export function findingAgeDays(finding: { detectedAt?: string | null }, nowMs: number): number | null {
  if (!finding.detectedAt) return null
  const parsed = new Date(finding.detectedAt)
  if (Number.isNaN(parsed.getTime())) return null
  return Math.max(0, Math.floor((nowMs - parsed.getTime()) / 86_400_000))
}

export interface FindingFilterOmit {
  organization?: boolean
  repository?: boolean
  source?: boolean
  keyType?: boolean
  statusFilter?: boolean
  ageBucket?: boolean
  search?: boolean
  classification?: boolean
}

export function formatTimestamp(value: string | null | undefined) {
  if (!value) return "Not available"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return "Not available"
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  })
}

function pickRawString(record: Record<string, unknown>, keys: string[]) {
  for (const key of keys) {
    const value = record[key]
    if (typeof value === "string" && value.trim()) return value.trim()
  }
  return null
}

function nestedRaw(record: Record<string, unknown>, path: string[]) {
  let current: unknown = record
  for (const segment of path) {
    if (!current || typeof current !== "object") return {}
    current = (current as Record<string, unknown>)[segment]
  }
  return current && typeof current === "object" ? (current as Record<string, unknown>) : {}
}

function findingCommitDateValue(finding: SecretFinding) {
  const raw = finding.raw ?? {}
  const git = nestedRaw(raw, ["SourceMetadata", "Data", "Git"])
  return (
    pickRawString(raw, ["Date", "commitDate", "CommitDate", "date", "timestamp", "CreatedAt", "detectedAt"]) ??
    pickRawString(git, ["timestamp", "Date", "date"]) ??
    finding.detectedAt
  )
}

export function findingCommitDate(finding: SecretFinding) {
  const value = findingCommitDateValue(finding)
  if (!value) return null
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return null
  return date
}

export function dateInputValue(date: Date) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`
}

export function matchesFindingFilters(
  finding: SecretFinding,
  filters: FindingFilterState,
  omit: FindingFilterOmit = {}
) {
  const query = filters.search.trim().toLowerCase()
  const matchesOrganization = omit.organization || !filters.organization || finding.organization.toLowerCase() === filters.organization.toLowerCase()
  const matchesRepo = omit.repository || !filters.repository || finding.repository === filters.repository
  const matchesSource = omit.source || !filters.source || finding.source === filters.source
  const matchesKeyType = omit.keyType || filters.keyType.length === 0 || filters.keyType.includes(finding.detector)
  const matchesStatus = omit.statusFilter || !filters.statusFilter || finding.reviewStatus === filters.statusFilter
  const matchesAge = omit.ageBucket || !filters.ageBucket || (() => {
    const bucket = AGE_BUCKETS.find((b) => b.label === filters.ageBucket)
    if (!bucket) return true
    const days = findingAgeDays(finding, filters.nowMs)
    if (days === null) return false
    return days >= bucket.minDays && days < bucket.maxDays
  })()
  const matchesQuery =
    omit.search ||
    !query ||
    finding.organization.toLowerCase().includes(query) ||
    finding.repository.toLowerCase().includes(query) ||
    finding.detector.toLowerCase().includes(query) ||
    finding.secretSnippet.toLowerCase().includes(query) ||
    (finding.filePath?.toLowerCase().includes(query) ?? false)
  const resolvedVerdict = resolveClassification(finding.classificationHistory)?.value ?? ""
  const matchesClassification =
    omit.classification ||
    filters.classificationFilter.length === 0 ||
    filters.classificationFilter.includes(resolvedVerdict)
  const matchesNewFindings = !filters.newFindings || !filters.lastScanDate || (finding.detectedAt != null && finding.detectedAt >= filters.lastScanDate)

  return matchesOrganization && matchesRepo && matchesSource && matchesKeyType && matchesStatus && matchesAge && matchesQuery && matchesClassification && matchesNewFindings
}

export function reviewTone(status: SecretReviewStatus) {
  if (status === "confirmed") return "bg-red-50 text-red-700 border-red-200 dark:bg-red-900/20 dark:text-red-300 dark:border-red-800"
  if (status === "false_positive") return "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-300 dark:border-emerald-800"
  if (status === "action_taken") return "bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-900/20 dark:text-blue-300 dark:border-blue-800"
  return "bg-slate-50 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700"
}

export function reviewStatusLabel(status: SecretReviewStatus) {
  if (status === "confirmed") return "Confirmed"
  if (status === "false_positive") return "False Positive"
  if (status === "action_taken") return "Action Taken"
  return "New"
}

export function findingUiIdentity(finding: SecretFinding) {
  return [
    finding.id,
    finding.organization,
    finding.repository,
    finding.source,
    finding.detector,
    finding.fingerprint,
    finding.filePath ?? "",
    finding.line ?? "",
    finding.commit ?? "",
    finding.detectedAt ?? "",
    finding.secretSnippet,
  ].join("::")
}

export function uniqueFindingKey(finding: SecretFinding) {
  return `${finding.organization.toLowerCase()}:${finding.secretIdentity ?? finding.fingerprint}`
}

export function dedupeFindings(findings: SecretFinding[]) {
  const unique = new Map<string, SecretFinding>()
  for (const finding of findings) {
    const key = uniqueFindingKey(finding)
    const existing = unique.get(key)
    if (!existing) {
      unique.set(key, finding)
      continue
    }

    const existingDate = findingCommitDate(existing)?.getTime() ?? 0
    const nextDate = findingCommitDate(finding)?.getTime() ?? 0
    if (nextDate > existingDate) {
      unique.set(key, finding)
    }
  }
  return Array.from(unique.values())
}

export function runProgressValue(run: SecretScanRun | null) {
  if (run?.status === "completed") return 100
  if (run?.status === "ingesting") return 95

  const expectedRepos = run?.progress?.expectedRepos
  const finishedRepos = run?.progress?.finishedRepos ?? 0
  if (expectedRepos && expectedRepos > 0 && run?.status === "running") {
    return Math.min(94, Math.max(finishedRepos > 0 ? 2 : 1, (finishedRepos / expectedRepos) * 94))
  }

  const candidate = run?.progress?.percent
  if (typeof candidate === "number" && Number.isFinite(candidate)) {
    return Math.max(0, Math.min(100, candidate))
  }
  if (run?.status === "queued") return 1
  if (run?.status === "running") return 2
  return 0
}

export function formatElapsed(startValue: string | null | undefined, nowMs: number) {
  if (!startValue) return "0s"
  const startMs = new Date(startValue).getTime()
  if (Number.isNaN(startMs)) return "0s"

  const seconds = Math.max(0, Math.floor((nowMs - startMs) / 1000))
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = seconds % 60

  if (h > 0) return `${h}h ${m}m ${s}s`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

// ---------------------------------------------------------------------------
// Classification resolution
// ---------------------------------------------------------------------------
// Priority: scanner > ai, then by classification severity, then most recent.
// A scanner-verified finding must never be downgraded by a later uncertain AI scan.

const SOURCE_PRIORITY: Record<string, number> = { scanner: 2, ai: 1 }

const VALUE_PRIORITY: Record<string, number> = {
  verified_secret: 4,
  likely_secret:   3,
  confirmed:       3, // legacy
  likely_real:     3, // legacy
  uncertain:       2,
  not_secret:      1,
  false_positive:  1, // legacy
}

export function resolveClassification(
  history: ClassificationEntry[] | null | undefined,
): ClassificationEntry | null {
  if (!history || history.length === 0) return null
  return history.reduce((best, entry) => {
    const bestScore = (SOURCE_PRIORITY[best.source] ?? 0) * 10 + (VALUE_PRIORITY[best.value] ?? 0)
    const entryScore = (SOURCE_PRIORITY[entry.source] ?? 0) * 10 + (VALUE_PRIORITY[entry.value] ?? 0)
    if (entryScore > bestScore) return entry
    if (entryScore === bestScore) {
      return new Date(entry.scannedAt) > new Date(best.scannedAt) ? entry : best
    }
    return best
  }, history[0])
}
