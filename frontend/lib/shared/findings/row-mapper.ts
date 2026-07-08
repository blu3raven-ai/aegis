import type { Finding as ApiFinding } from "../../client/findings-api.ts"
import { timeAgo } from "../time-ago.ts"
import type { Verdict } from "./verdicts.ts"

export type FindingSeverity = "critical" | "high" | "medium" | "low"
export type FindingActionBand = "act" | "attend" | "track"
export type FindingScanner =
  | "dependencies_scanning"
  | "code_scanning"
  | "container_scanning"
  | "secret_scanning"
  | "iac_scanning"
  | "agent_scanning"

/** One step in a secret-rotation runbook (secrets `rotation` fix). */
export interface FindingRecommendedFixStep {
  order: number
  label: string
  detail?: string
  /** Console/dashboard URL for this step, when one exists. */
  url?: string
  /** A CLI command the operator can copy to perform the step. */
  cli?: string
  /** Irreversible step (e.g. revoking the live key) — surfaced as a warning. */
  destructive?: boolean
}

/**
 * Server-supplied remediation payload — a discriminated union keyed by `kind`:
 * deps emit `upgrade` (the original, default shape), SAST `code_patch`, IaC
 * `config_patch`, secrets `rotation`. Every field is optional and additive so
 * older payloads (which omit `kind` and carry only the upgrade fields) keep
 * rendering exactly as before.
 */
export interface FindingRecommendedFix {
  kind?: "upgrade" | "code_patch" | "config_patch" | "rotation"
  /** Optional one-line title, e.g. "Upgrade log4j-core". */
  title?: string
  /** Free-form description, e.g. "Patch release · no API changes". */
  description?: string
  /** Why this fix is recommended. */
  rationale?: string
  /** How sure the source is about the fix. */
  confidence?: "high" | "medium" | "low"
  /** Whether the fix has been validated (e.g. build/tests pass). */
  validated?: boolean
  /** Where the fix came from. */
  source?: "synthesized" | "deterministic" | "llm"

  // upgrade (dependencies)
  packageName?: string
  fromVersion?: string
  toVersion?: string
  /** Snippet payload copied to clipboard by the drawer's Copy button. */
  snippet?: string
  /** Optional URL to a diff view. */
  diffUrl?: string

  // code_patch (SAST) — filePath/diff are shared with config_patch
  filePath?: string
  diff?: string
  startLine?: number
  endLine?: number

  // config_patch (IaC)
  resource?: string
  before?: string
  after?: string

  // rotation (secrets)
  provider?: string
  verifiedActive?: boolean
  steps?: FindingRecommendedFixStep[]
}

/** Where a piece of verification evidence sits in the taint path. */
export type VerificationEvidenceKind = "source" | "sink" | "gate"

/** One cited line the verifier relied on to reach its verdict. */
export interface VerificationEvidence {
  file: string
  line: number
  snippet: string
  kind: VerificationEvidenceKind
}

/** The upstream mitigation a `ruled_out` verdict points to. */
export interface VerificationRuledOutReason {
  file?: string | null
  line?: number | null
  snippet?: string | null
  reasoning?: string | null
}

/**
 * Verifier run metadata — model + token spend, plus the ruled-out mitigation
 * when one was found, or a `skipped` reason when verification didn't run. The
 * backend passes its JSONB column through untouched, so keys stay snake_case.
 */
export interface VerificationMetadata {
  model?: string
  tokens_in?: number
  tokens_out?: number
  ruled_out_reason?: VerificationRuledOutReason
  skipped?: string
  /**
   * Provenance the verifier records when it runs. `tier`/`escalated` are
   * populated once the tiered-model escalation path ships; the drawer renders
   * them only when present, so this stays honest until the backend writes them.
   */
  tier?: string
  escalated?: boolean
  latency_ms?: number
  /**
   * Why the verifier couldn't confirm a finding. `reason` is a single machine
   * code (e.g. `hunter_no_chain`, `package_not_imported`, `schema_invalid: …`);
   * the list keys carry the citations that failed grounding. Rendered as prose
   * by `verdictRationale`.
   */
  reason?: string
  unverified_citations?: string[]
  suppression_downgraded?: string[]
  ungrounded_no_path?: string[]
  /** Deps reachability signal: `reachable` | `no_path` | `unknown`. */
  reachability?: string
  [k: string]: unknown
}

/** Runner-derived reachability of a vulnerable dependency symbol. */
export type Reachability = "reachable" | "no_path" | "unknown"

/** Image context for a container finding. */
export interface FindingContainerImage {
  name: string
  tag?: string
  digest?: string
  baseOs?: string
  layerCount?: number
  /** Layer that introduced the vulnerable package: digest + 0-based ordinal. */
  layerDigest?: string
  layerIndex?: number
  /** Newer registry tags available for this image (opt-in tag listing). */
  newerTags?: string[]
  /** Most-affected layer across this image's open findings (detail-fetch only). */
  layerConcentration?: { layerIndex: number; findingCount: number; totalWithLayer: number }
  /** Newer base tag with fewer vulns, proven by rescanning (detail-fetch only). */
  baseImageRecommendation?: { recommendedTag: string; currentVulnCount: number; recommendedVulnCount: number }
}

export interface FindingRow {
  id: string
  title: string
  cve?: string
  /** Affected package as `name@version` (dependency/container findings). */
  package?: string
  severity: FindingSeverity
  scanner: FindingScanner
  repo: string
  /** Concrete repo web URL (self-hosted hosts); enables the view-in-repo link. */
  repoHtmlUrl?: string
  filePath?: string
  age: string
  riskScore?: number
  /** SSVC-style triage band derived from KEV + reachability + severity. */
  actionBand?: FindingActionBand
  /** EPSS percentile in [0.0, 1.0] from the FIRST.org feed (Phase 50). */
  epssPercentile?: number
  /** Lifecycle state from the aggregated endpoint — null when the server omits it. */
  state?: string
  /** Whether the finding's CVE is in CISA KEV (server-supplied). */
  kev?: boolean
  /** Malicious-package report (OSV MAL-): remove the package, don't upgrade. */
  malicious?: boolean
  /** First CWE id (e.g. "CWE-502") from KEV metadata. */
  cwe?: string
  /** ISO timestamp of when the finding was first detected. */
  firstSeen?: string
  /** Short SHA of the commit that introduced the finding. */
  introducedByCommit?: string
  /** Author handle (e.g. "@maya.l") credited with introducing the finding. */
  introducedByAuthor?: string
  /** PR URL that introduced the finding, when known. */
  introducedByPrUrl?: string
  /** Server-supplied recommended fix payload; absent when no fix is known. */
  recommendedFix?: FindingRecommendedFix
  /** Assigned reviewer's user id, or undefined when unassigned. */
  assigneeUserId?: string
  /** Argus-verification verdict, when the org runs the verification pass. */
  verdict?: Verdict
  /** One-line disproof for ruled-out findings; shown inline on the audit view. */
  ruledOutReason?: string
  /** Short, client-safe code/context preview (redacted for secrets). */
  codeSnippet?: string
  /** 1-indexed file line of the snippet's first line, for gutter anchoring. */
  codeSnippetStartLine?: number
  /** Offending line range to highlight within the snippet. */
  highlightStart?: number
  highlightEnd?: number
  /** Scanner's explanation of the issue (what's wrong). */
  description?: string
  /** Rule that fired (name or id). */
  rule?: string
  /** Remediation guidance (how to fix). */
  remediation?: string
  /** Scanner confidence (e.g. "high"). */
  confidence?: string
  /** Secret detector that fired (e.g. "AWS secret"). Secret findings only. */
  secretDetector?: string
  /** Whether the secret was confirmed live; undefined when not validated. */
  secretVerified?: boolean
  /** Blast radius: other in-scope repos sharing this CVE/package (detail fetch only). */
  alsoAffectsRepos?: number
  /** Image context for container findings (detail fetch only). */
  containerImage?: FindingContainerImage
  /** Ordered taint path (source → sink) for SAST flow findings. */
  codeFlows?: CodeFlowStep[]
  /** Cited source/sink/gate lines behind the Argus verdict (detail fetch only). */
  evidence?: VerificationEvidence[]
  /** Verifier's exploit-chain narrative (detail fetch only). */
  exploitChain?: string
  /** Verifier model/token footer + ruled-out mitigation (detail fetch only). */
  verificationMetadata?: VerificationMetadata
  /** Runner-derived reachability for deps findings (detail fetch only). */
  reachability?: Reachability
}

export interface CodeFlowStep {
  file: string
  line: number
  snippet?: string
}

// Canonical scanner names use the `<thing>_scanning` suffix. Unknown
// values fall back to dependencies-scanning styling rather than crashing
// the row.
const SCANNER_MAP: Record<string, FindingScanner> = {
  dependencies_scanning: "dependencies_scanning",
  code_scanning: "code_scanning",
  container_scanning: "container_scanning",
  secret_scanning: "secret_scanning",
  iac_scanning: "iac_scanning",
  agent_scanning: "agent_scanning",
  // The REST detail endpoint returns the backend's public shorthand (see
  // _TOOL_TO_PUBLIC), so a finding opened via getFindingDetail arrives with
  // these. Map them too — otherwise the shorthand fell through to the
  // dependencies fallback and every non-deps finding opened by deep-link was
  // mislabeled a dependency (e.g. a secret showing the deps reachability panel).
  deps: "dependencies_scanning",
  sast: "code_scanning",
  container: "container_scanning",
  secrets: "secret_scanning",
  iac: "iac_scanning",
  agent: "agent_scanning",
}

export function normaliseScanner(raw: string): FindingScanner {
  return SCANNER_MAP[raw] ?? "dependencies_scanning"
}

export function normaliseSeverity(raw: string | null): FindingSeverity {
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low") {
    return raw
  }
  return "low"
}

export function normaliseActionBand(raw: string | null | undefined): FindingActionBand | undefined {
  if (raw === "act" || raw === "attend" || raw === "track") {
    return raw
  }
  return undefined
}

export function normaliseReachability(
  raw: string | null | undefined,
): Reachability | undefined {
  if (raw === "reachable" || raw === "no_path" || raw === "unknown") {
    return raw
  }
  return undefined
}

/**
 * Coerce the server's JSONB evidence array into typed citations. Unknown
 * `kind` values fall back to `gate` so a malformed item still renders rather
 * than breaking the list; items missing a snippet are dropped (nothing to show).
 */
function normaliseEvidence(
  raw: ApiFinding["evidence"],
): VerificationEvidence[] | undefined {
  // Some scanners (e.g. agent) persist evidence as a non-array JSONB object;
  // guard on the array shape so an unexpected value is ignored rather than
  // crashing the whole detail load on a non-iterable.
  if (!Array.isArray(raw) || raw.length === 0) return undefined
  const out: VerificationEvidence[] = []
  for (const e of raw) {
    if (!e || !e.snippet) continue
    const kind: VerificationEvidenceKind =
      e.kind === "source" || e.kind === "sink" || e.kind === "gate" ? e.kind : "gate"
    out.push({
      file: cleanWorkspacePath(e.file || ""),
      line: e.line ?? 0,
      snippet: e.snippet,
      kind,
    })
  }
  return out.length > 0 ? out : undefined
}

function buildRepoLabel(api: ApiFinding): string {
  if (api.repo) return api.repo
  if (api.package) return api.package
  return api.org_id
}

/**
 * Strip the runner's clone-dir scaffolding so a path reads repo-relative
 * instead of leaking the scanner's working directory: the ephemeral
 * ".../workspace/job-<hash>/" prefix, then the "<repo>/_checkout/" prefix that
 * semgrep/checkov paths carry (they run against the absolute clone dir). The
 * "_checkout/" re-anchoring mirrors the backend resolver so display and
 * file-resolution agree on the repo-relative path.
 */
function cleanWorkspacePath(path: string): string {
  const stripped = path
    .replace(/^.*?\/workspace\/job-[0-9a-f]+\//i, "")
    .replace(/^\/+/, "")
  const marker = "_checkout/"
  const idx = stripped.lastIndexOf(marker)
  return idx === -1 ? stripped : stripped.slice(idx + marker.length)
}

function buildFilePath(api: ApiFinding): string | undefined {
  if (!api.file_path) return undefined
  const path = cleanWorkspacePath(api.file_path)
  return api.line != null ? `${path}:${api.line}` : path
}

/** Readable "basename:line" label from the structured file fields. */
function fileLabel(api: ApiFinding): string | undefined {
  if (!api.file_path) return undefined
  const file = cleanWorkspacePath(api.file_path).split("/").pop() || api.file_path
  return api.line != null ? `${file}:${api.line}` : file
}

/**
 * Some scanners use an opaque identity as the title: code-scanning leaks the
 * clone path + full rule id ("repo:/workspace/job-…/server.py:rule.path:93"),
 * and secret-scanning uses a hash of the secret value. Neither is readable, so
 * fall back to a file-location label from the structured fields.
 */
function buildTitle(api: ApiFinding): string {
  const raw = api.title ?? api.cve ?? ""
  const loc = fileLabel(api)
  if (loc && raw.includes("/workspace/job-")) {
    return loc
  }
  if (loc && normaliseScanner(api.scanner) === "secret_scanning" && /^[0-9a-f]{16,}$/i.test(raw)) {
    return `Secret in ${loc}`
  }
  return raw || "Untitled finding"
}

function buildAge(api: ApiFinding): string {
  const ts = api.created_at ?? api.updated_at
  if (!ts) return "—"
  return timeAgo(ts)
}

export function mapApiFinding(api: ApiFinding): FindingRow {
  return {
    id: api.id,
    title: buildTitle(api),
    cve: api.cve ?? undefined,
    package: api.package ?? undefined,
    severity: normaliseSeverity(api.severity),
    scanner: normaliseScanner(api.scanner),
    repo: buildRepoLabel(api),
    repoHtmlUrl: api.repo_html_url ?? undefined,
    filePath: buildFilePath(api),
    age: buildAge(api),
    epssPercentile: api.epssPercentile ?? undefined,
    state: api.state ?? undefined,
    firstSeen: api.created_at ?? undefined,
    kev: api.kev ?? undefined,
    malicious: api.malicious ?? undefined,
    cwe: api.cwe ?? undefined,
    riskScore: api.risk_score ?? undefined,
    actionBand: normaliseActionBand(api.action_band),
    assigneeUserId: api.assignee_user_id ?? undefined,
    verdict: api.verdict ?? undefined,
    ruledOutReason: api.ruled_out_reason ?? undefined,
    codeSnippet: api.code_snippet ?? undefined,
    codeSnippetStartLine: api.code_snippet_start_line ?? undefined,
    highlightStart: api.code_highlight_start ?? undefined,
    highlightEnd: api.code_highlight_end ?? undefined,
    description: api.description ?? undefined,
    rule: api.rule ?? undefined,
    remediation: api.remediation ?? undefined,
    confidence: api.confidence ?? undefined,
    secretDetector: api.secret_detector ?? undefined,
    secretVerified: api.secret_verified ?? undefined,
    alsoAffectsRepos: api.also_affects_repos ?? undefined,
    containerImage: api.container_image
      ? {
          name: api.container_image.name,
          tag: api.container_image.tag ?? undefined,
          digest: api.container_image.digest ?? undefined,
          baseOs: api.container_image.base_os ?? undefined,
          layerCount: api.container_image.layer_count ?? undefined,
          layerDigest: api.container_image.layer_digest ?? undefined,
          layerIndex: api.container_image.layer_index ?? undefined,
          newerTags: api.container_image.newer_tags ?? undefined,
          layerConcentration: api.container_image.layer_concentration
            ? {
                layerIndex: api.container_image.layer_concentration.layer_index,
                findingCount: api.container_image.layer_concentration.finding_count,
                totalWithLayer: api.container_image.layer_concentration.total_with_layer,
              }
            : undefined,
          baseImageRecommendation: api.container_image.base_image_recommendation
            ? {
                recommendedTag: api.container_image.base_image_recommendation.recommended_tag,
                currentVulnCount: api.container_image.base_image_recommendation.current_vuln_count,
                recommendedVulnCount:
                  api.container_image.base_image_recommendation.recommended_vuln_count,
              }
            : undefined,
        }
      : undefined,
    introducedByCommit: api.introduced_by_commit ?? undefined,
    codeFlows: api.code_flows
      ? api.code_flows.map((s) => ({
          file: cleanWorkspacePath(s.file || ""),
          line: s.line ?? 0,
          snippet: s.snippet || undefined,
        }))
      : undefined,
    recommendedFix: api.recommended_fix ?? undefined,
    evidence: normaliseEvidence(api.evidence),
    exploitChain: api.exploit_chain ?? undefined,
    verificationMetadata: api.verification_metadata ?? undefined,
    reachability: normaliseReachability(api.reachability),
  }
}
