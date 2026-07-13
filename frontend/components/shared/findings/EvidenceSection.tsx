"use client"

import { VerdictBadge } from "@/components/shared/findings/VerdictBadge"
import { LinkButton } from "@/components/ui/LinkButton"
import type { Verdict } from "@/lib/shared/findings/verdicts"
import { verdictRationale } from "@/lib/shared/findings/verdict-rationale"
import type {
  FindingScanner,
  VerificationEvidence,
  VerificationEvidenceKind,
  VerificationMetadata,
} from "@/lib/shared/findings/row-mapper"

type Props = {
  verdict: Verdict | undefined
  evidence: VerificationEvidence[] | null | undefined
  exploitChain: string | null | undefined
  metadata: VerificationMetadata | null | undefined
  /** Whether LLM verification is enabled. When false, the panel shows a locked preview. */
  verificationEnabled: boolean
  /** Whether the LLM verifier covers this finding's scanner type (SAST / IaC / deps). */
  verifiable: boolean
  /** Drives which locked-preview copy shows — deps get reachability framing. */
  scanner: FindingScanner
}

const KIND_COLOR: Record<VerificationEvidenceKind, string> = {
  source: "text-[var(--color-severity-medium-text)]",
  sink: "text-[var(--color-severity-critical-text)]",
  gate: "text-[var(--color-status-ok-text)]",
}

/** DOM id for the nth evidence row, so a chain citation can scroll to it. */
const evidenceRefId = (n: number) => `finding-evidence-r${n}`

/**
 * Render the exploit-chain narrative, turning `[R1]`-style citations into
 * clickable chips that jump to the matching evidence row. Citations past the
 * evidence count (the model over-cited) fall back to plain text, so a stray
 * `[R9]` never produces a dead link.
 */
function renderChainWithRefs(chain: string, refCount: number): React.ReactNode {
  return chain.split(/(\[R\d+\])/g).map((part, i) => {
    const match = /^\[R(\d+)\]$/.exec(part)
    const n = match ? Number(match[1]) : 0
    if (n >= 1 && n <= refCount) {
      return (
        <a
          key={i}
          href={`#${evidenceRefId(n)}`}
          onClick={(e) => {
            e.preventDefault()
            document
              .getElementById(evidenceRefId(n))
              ?.scrollIntoView({ behavior: "smooth", block: "center" })
          }}
          className="mx-0.5 inline-flex items-center rounded bg-[var(--color-surface-raised)] px-1 font-mono text-2xs font-semibold text-[var(--color-accent)] no-underline hover:bg-[var(--color-accent-subtle)]"
        >
          R{n}
        </a>
      )
    }
    return part
  })
}

/**
 * The emphasized "Impact" callout — a red-bordered block with an inline IMPACT
 * label. Shared so a scanner's curated advisory (e.g. the agent scanner) can be
 * given the same visual weight as a verifier-authored impact statement.
 */
export function ImpactCallout({ children }: { children: React.ReactNode }) {
  return (
    <p className="rounded-md border-l-2 border-[var(--color-severity-high)] bg-[var(--color-severity-high-subtle)] px-3 py-2 text-sm font-medium leading-relaxed text-[var(--color-text-primary)]">
      <span className="mr-1.5 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-severity-high-text)]">Impact</span>
      {children}
    </p>
  )
}

/** Tint a unified-diff line: additions green, removals red, hunk headers muted. */
function diffLineClass(line: string): string {
  if (line.startsWith("+") && !line.startsWith("+++")) return "text-[var(--color-severity-low-text)]"
  if (line.startsWith("-") && !line.startsWith("---")) return "text-[var(--color-severity-critical-text)]"
  if (line.startsWith("@@")) return "text-[var(--color-text-tertiary)]"
  return "text-[var(--color-text-secondary)]"
}

/**
 * The locked-preview copy differs by what the verifier actually does for that
 * scanner: SAST/IaC get an exploit-path pass; dependencies get a
 * reachability pass. Anything but honest framing would over-promise.
 */
const LOCKED_PREVIEW = {
  exploit: {
    teaserChip: "🔴 Confirmed",
    teaserText:
      "A tainted request parameter flows unsanitised into a SQL query, confirming an exploitable injection path from the request handler to the database call.",
    teaserLabel: "source · app/views.py:14",
    teaserCode: 'q = request.GET["q"]',
    title: "Enable LLM verification to verify this finding",
    body: "Your model runs an AI exploit-verification pass — confirming real exploits with a cited evidence chain and ruling out false positives.",
  },
  reachability: {
    teaserChip: "🔴 Reachable",
    teaserText:
      "The vulnerable deserialize() path is imported and invoked from your request handler, confirming your code actually reaches this CVE.",
    teaserLabel: "import · src/api/parse.ts:12",
    teaserCode: "parse(userInput)",
    title: "Enable LLM verification to check reachability",
    body: "Your model checks whether your code actually reaches this vulnerable dependency — flagging reachable risks and ruling out unreachable ones.",
  },
} as const

type LockedPreviewVariant = keyof typeof LOCKED_PREVIEW

/** Blurred, non-interactive teaser of what verification produces, behind an
 *  "Enable verification" call-to-action — shown when it isn't set up yet. */
function VerificationLockedPreview({ variant }: { variant: LockedPreviewVariant }) {
  const copy = LOCKED_PREVIEW[variant]
  return (
    <section>
      <h3 className="mb-2 text-base font-semibold text-[var(--color-text-primary)]">
        Verification
      </h3>
      <div className="relative overflow-hidden rounded border border-[var(--color-border)]">
        <div
          aria-hidden="true"
          className="pointer-events-none select-none space-y-2 p-3 opacity-70 blur-[3px]"
        >
          <span className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-2xs font-semibold bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical-text)]">
            {copy.teaserChip}
          </span>
          <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">{copy.teaserText}</p>
          <div className="rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] p-2">
            <div className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-severity-medium-text)]">
              {copy.teaserLabel}
            </div>
            <pre className="mt-1 rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-2 font-mono text-xs">
              {copy.teaserCode}
            </pre>
          </div>
        </div>

        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-[color-mix(in_srgb,var(--color-surface)_55%,transparent)] px-4 text-center">
          <svg viewBox="0 0 24 24" className="h-5 w-5 text-[var(--color-accent)]" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <rect x="3" y="11" width="18" height="11" rx="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          <p className="text-sm font-semibold text-[var(--color-text-primary)]">{copy.title}</p>
          <p className="max-w-xs text-xs text-[var(--color-text-secondary)]">{copy.body}</p>
          <LinkButton href="/settings#llm" variant="primary" size="sm" trailingIcon={<span aria-hidden="true">→</span>}>
            Enable verification
          </LinkButton>
        </div>
      </div>
    </section>
  )
}

/**
 * The "why this verdict" block for the finding drawer: the verifier's
 * exploit-chain narrative, the source/sink/gate lines it cited, the upstream
 * mitigation behind a `ruled_out` verdict, and the model/token footer. When the
 * verifier hasn't run, shows a locked preview (verifiable scanners only); null
 * when there's nothing to say.
 */
export function EvidenceSection({
  verdict,
  evidence,
  exploitChain,
  metadata,
  verificationEnabled,
  verifiable,
  scanner,
}: Props) {
  const hasChain = Boolean(exploitChain)
  const hasEvidence = Boolean(evidence && evidence.length > 0)
  const refCount = evidence?.length ?? 0
  const impact = metadata?.impact?.trim()
  const reproduction = metadata?.reproduction?.trim()
  const attackPaths = (metadata?.attack_paths ?? []).filter((p) => p?.steps?.trim())
  const mitigatingFactors = (metadata?.mitigating_factors ?? []).filter((f) => f?.trim())
  const fix = metadata?.fix?.trim()
  const fixIsDiff = Boolean(fix && /^(---|\+\+\+|@@|[+-] )/m.test(fix))
  const ruledOut = metadata?.ruled_out_reason
  const rationale = verdictRationale(verdict, metadata)
  // A proposed mitigation whose citation failed grounding: the finding was NOT
  // ruled out, so the mitigation block must read as unconfirmed, not clean.
  const mitigationUnconfirmed = Boolean(
    metadata?.suppression_downgraded && metadata.suppression_downgraded.length > 0,
  )
  const hasMetadata = Boolean(
    metadata?.model || metadata?.tokens_in || metadata?.tier || metadata?.escalated,
  )
  const hasReasoning =
    hasChain || hasEvidence || Boolean(ruledOut) || Boolean(rationale) || hasMetadata

  // No verification reasoning on this finding: offer the locked preview when
  // verification isn't enabled and this scanner is one the verifier covers.
  if (!hasReasoning) {
    if (!verificationEnabled && verifiable) {
      const variant = scanner === "dependencies_scanning" ? "reachability" : "exploit"
      return <VerificationLockedPreview variant={variant} />
    }
    return null
  }

  return (
    <section>
      <div className="mb-2 flex items-center gap-2">
        <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
          Verification
        </h3>
        {verdict && <VerdictBadge verdict={verdict} />}
      </div>

      {rationale && (
        <p
          className={
            rationale.tone === "caution"
              ? "mb-3 border-l-2 border-[var(--color-severity-medium-border)] pl-3 py-0.5 text-sm leading-relaxed text-[var(--color-text-primary)]"
              : "mb-3 border-l-2 border-[var(--color-border)] pl-3 py-0.5 text-sm leading-relaxed text-[var(--color-text-secondary)]"
          }
        >
          {rationale.text}
        </p>
      )}

      {impact && <ImpactCallout>{impact}</ImpactCallout>}

      {hasChain && (
        <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">
          {renderChainWithRefs(exploitChain!, refCount)}
        </p>
      )}

      {/* Technical detail (the cited evidence) sits right after the summary,
          before the attack scenario — advisory reading order. Citation anchors
          (evidenceRefId) are unchanged, so [R1] links still resolve. */}
      {hasEvidence && (
        <ul className="mt-3 space-y-2">
          {evidence!.map((e, i) => (
            <li
              key={i}
              id={evidenceRefId(i + 1)}
              className="scroll-mt-4 rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] p-2 target:ring-1 target:ring-[var(--color-accent)]"
            >
              <div className="flex items-center justify-between gap-3 text-2xs font-semibold uppercase tracking-[0.14em]">
                <span className="flex items-center gap-1.5">
                  <span className="rounded bg-[var(--color-surface-raised)] px-1 font-mono normal-case tracking-normal text-[var(--color-text-tertiary)]">
                    R{i + 1}
                  </span>
                  <span className={KIND_COLOR[e.kind] || "text-[var(--color-text-secondary)]"}>
                    {e.kind}
                  </span>
                </span>
                <span
                  className="truncate text-[var(--color-text-secondary)]"
                  title={`${e.file}:${e.line}`}
                >
                  {e.file}:{e.line}
                </span>
              </div>
              <pre className="mt-1 whitespace-pre-wrap break-all rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-2 font-mono text-xs leading-relaxed">
                {e.snippet}
              </pre>
            </li>
          ))}
        </ul>
      )}

      {attackPaths.length > 0 && (
        <div className="mt-3">
          <h4 className="mb-1.5 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            Attack paths
          </h4>
          <ol className="space-y-2">
            {attackPaths.map((p, i) => (
              <li key={i} className="rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] p-2">
                {p.name && (
                  <p className="mb-1 text-xs font-semibold text-[var(--color-text-primary)]">{p.name}</p>
                )}
                <p className="text-sm leading-relaxed text-[var(--color-text-secondary)]">
                  {renderChainWithRefs(p.steps, refCount)}
                </p>
              </li>
            ))}
          </ol>
        </div>
      )}

      {mitigatingFactors.length > 0 && (
        <div className="mt-3">
          <h4 className="mb-1.5 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            Mitigating factors
          </h4>
          <ul className="list-disc space-y-1 pl-5 text-sm text-[var(--color-text-secondary)]">
            {mitigatingFactors.map((f, i) => (
              <li key={i}>{f}</li>
            ))}
          </ul>
        </div>
      )}

      {fix && (
        <div className="mt-3">
          <h4 className="mb-1.5 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            Suggested fix
          </h4>
          {fixIsDiff ? (
            <pre className="overflow-x-auto rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-3 font-[family-name:var(--font-jetbrains-mono)] text-[12px] leading-relaxed">
              {fix.split("\n").map((line, i) => (
                <div key={i} className={diffLineClass(line)}>{line || " "}</div>
              ))}
            </pre>
          ) : (
            <p className="text-sm leading-relaxed text-[var(--color-text-secondary)]">{fix}</p>
          )}
        </div>
      )}

      {reproduction && (
        <div className="mt-3">
          <h4 className="mb-1 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            Proof of concept
          </h4>
          <pre className="whitespace-pre-wrap break-words rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-2 font-mono text-xs leading-relaxed text-[var(--color-text-primary)]">
            {reproduction}
          </pre>
        </div>
      )}

      {ruledOut && (ruledOut.reasoning || ruledOut.snippet) && (
        <div
          className={
            mitigationUnconfirmed
              ? "mt-3 border-l-2 border-[var(--color-severity-medium-border)] pl-3"
              : "mt-3 border-l-2 border-[var(--color-status-ok-border)] pl-3"
          }
        >
          <h4
            className={
              mitigationUnconfirmed
                ? "mb-1 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-severity-medium-text)]"
                : "mb-1 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-status-ok-text)]"
            }
          >
            {mitigationUnconfirmed ? "Unconfirmed mitigation" : "Mitigation found"}
          </h4>
          {mitigationUnconfirmed && (
            <p className="mb-1 text-2xs text-[var(--color-text-secondary)]">
              The verifier proposed this mitigation but couldn&apos;t confirm it in your code, so the finding was not ruled out.
            </p>
          )}
          {ruledOut.reasoning && <p className="text-sm leading-relaxed">{ruledOut.reasoning}</p>}
          {ruledOut.snippet && (
            <pre className="mt-2 whitespace-pre-wrap break-all rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-2 font-mono text-xs">
              {ruledOut.snippet}
            </pre>
          )}
          {ruledOut.file && (
            <div className="mt-1 text-2xs text-[var(--color-text-secondary)]">
              {ruledOut.file}
              {ruledOut.line ? `:${ruledOut.line}` : ""}
            </div>
          )}
        </div>
      )}

      {hasMetadata && <VerificationProvenance metadata={metadata!} />}
    </section>
  )
}

/**
 * "Verified by" provenance for a verified finding: which model ran the pass,
 * the token effort it cost, and — once the tiered-model escalation path writes
 * them — the tier and whether the verdict was escalated. Every field renders
 * only when the metadata carries it, so nothing is implied that didn't happen.
 */
function VerificationProvenance({ metadata }: { metadata: VerificationMetadata }) {
  const tokens =
    metadata.tokens_in || metadata.tokens_out
      ? `${(metadata.tokens_in ?? 0).toLocaleString()} in / ${(metadata.tokens_out ?? 0).toLocaleString()} out`
      : null
  const latency =
    typeof metadata.latency_ms === "number" ? `${(metadata.latency_ms / 1000).toFixed(1)}s` : null

  return (
    <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-2xs tabular-nums text-[var(--color-text-secondary)]">
      <span className="font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
        Verified by
      </span>
      {metadata.model && <span className="font-mono text-[var(--color-text-primary)]">{metadata.model}</span>}
      {metadata.tier && (
        <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-1.5 py-px capitalize text-[var(--color-text-secondary)]">
          {metadata.tier} tier
        </span>
      )}
      {metadata.escalated && (
        <span className="rounded-full border border-[color-mix(in_srgb,var(--color-severity-high)_40%,transparent)] bg-[color-mix(in_srgb,var(--color-severity-high)_12%,transparent)] px-1.5 py-px font-semibold text-[var(--color-severity-high-text)]">
          Escalated
        </span>
      )}
      {tokens && <span>· {tokens}</span>}
      {latency && <span>· {latency}</span>}
    </div>
  )
}
