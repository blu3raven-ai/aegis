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
}

export interface FindingRow {
  id: string
  title: string
  cve?: string
  severity: FindingSeverity
  scanner: FindingScanner
  repo: string
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
  if (!raw || raw.length === 0) return undefined
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
 * Strip the runner's ephemeral clone prefix (".../workspace/job-<hash>/") and
 * any leading slashes so a path reads repo-relative instead of leaking the
 * scanner's working directory.
 */
function cleanWorkspacePath(path: string): string {
  return path.replace(/^.*?\/workspace\/job-[0-9a-f]+\//i, "").replace(/^\/+/, "")
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
    severity: normaliseSeverity(api.severity),
    scanner: normaliseScanner(api.scanner),
    repo: buildRepoLabel(api),
    filePath: buildFilePath(api),
    age: buildAge(api),
    epssPercentile: api.epssPercentile ?? undefined,
    state: api.state ?? undefined,
    firstSeen: api.created_at ?? undefined,
    kev: api.kev ?? undefined,
    cwe: api.cwe ?? undefined,
    riskScore: api.risk_score ?? undefined,
    actionBand: normaliseActionBand(api.action_band),
    assigneeUserId: api.assignee_user_id ?? undefined,
    verdict: api.verdict ?? undefined,
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
