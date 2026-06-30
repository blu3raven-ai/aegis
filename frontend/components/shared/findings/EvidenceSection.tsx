"use client"

import { VerdictBadge } from "@/components/shared/findings/VerdictBadge"
import { LinkButton } from "@/components/ui/LinkButton"
import type { Verdict } from "@/lib/shared/findings/verdicts"
import type {
  VerificationEvidence,
  VerificationEvidenceKind,
  VerificationMetadata,
} from "@/lib/shared/findings/row-mapper"

type Props = {
  verdict: Verdict | undefined
  evidence: VerificationEvidence[] | null | undefined
  exploitChain: string | null | undefined
  metadata: VerificationMetadata | null | undefined
  /** Whether Argus is connected. When false, the panel shows a locked preview. */
  argusEnabled: boolean
  /** Whether Argus verifies this finding's scanner type (SAST / secrets / IaC). */
  verifiable: boolean
}

const KIND_COLOR: Record<VerificationEvidenceKind, string> = {
  source: "text-[var(--color-severity-medium)]",
  sink: "text-[var(--color-severity-critical)]",
  gate: "text-[var(--color-status-ok)]",
}

/** Blurred, non-interactive teaser of what Argus produces, behind an
 *  "Enable Argus" call-to-action — shown when Argus isn't connected yet. */
function ArgusLockedPreview() {
  return (
    <section className="mt-6">
      <h3 className="mb-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
        Verification
      </h3>
      <div className="relative overflow-hidden rounded border border-[var(--color-border)]">
        <div
          aria-hidden="true"
          className="pointer-events-none select-none space-y-2 p-3 opacity-70 blur-[3px]"
        >
          <span className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-2xs font-semibold bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]">
            🔴 Confirmed
          </span>
          <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">
            A tainted request parameter flows unsanitised into a SQL query, confirming an
            exploitable injection path from the request handler to the database call.
          </p>
          <div className="rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] p-2">
            <div className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-severity-medium)]">
              source · app/views.py:14
            </div>
            <pre className="mt-1 rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-2 font-mono text-xs">
              q = request.GET[&quot;q&quot;]
            </pre>
          </div>
        </div>

        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-[color-mix(in_srgb,var(--color-surface)_55%,transparent)] px-4 text-center">
          <svg viewBox="0 0 24 24" className="h-5 w-5 text-[var(--color-accent)]" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <rect x="3" y="11" width="18" height="11" rx="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          <p className="text-sm font-semibold text-[var(--color-text-primary)]">
            Enable Argus to verify this finding
          </p>
          <p className="max-w-xs text-xs text-[var(--color-text-secondary)]">
            Argus runs an AI exploit-verification pass — confirming real exploits with a cited
            evidence chain and ruling out false positives.
          </p>
          <LinkButton href="/settings#argus" variant="primary" size="sm" trailingIcon={<span aria-hidden="true">→</span>}>
            Enable Argus
          </LinkButton>
        </div>
      </div>
    </section>
  )
}

/**
 * The "why this verdict" block for the finding drawer: Argus's exploit-chain
 * narrative, the source/sink/gate lines it cited, the upstream mitigation behind
 * a `ruled_out` verdict, and the model/token footer. When Argus hasn't run, shows
 * a locked preview (verifiable scanners only); null when there's nothing to say.
 */
export function EvidenceSection({
  verdict,
  evidence,
  exploitChain,
  metadata,
  argusEnabled,
  verifiable,
}: Props) {
  const hasChain = Boolean(exploitChain)
  const hasEvidence = Boolean(evidence && evidence.length > 0)
  const ruledOut = metadata?.ruled_out_reason
  const hasMetadata = Boolean(metadata?.model || metadata?.tokens_in)
  const hasReasoning = hasChain || hasEvidence || Boolean(ruledOut) || hasMetadata

  // No Argus reasoning on this finding: offer the locked preview when Argus
  // isn't connected and this scanner is one Argus verifies; otherwise nothing.
  if (!hasReasoning) {
    if (!argusEnabled && verifiable) return <ArgusLockedPreview />
    return null
  }

  return (
    <section className="mt-6">
      <div className="mb-2 flex items-center gap-2">
        <h3 className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
          Verification
        </h3>
        {verdict && <VerdictBadge verdict={verdict} />}
      </div>

      {hasChain && (
        <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">{exploitChain}</p>
      )}

      {hasEvidence && (
        <ul className="mt-3 space-y-2">
          {evidence!.map((e, i) => (
            <li
              key={i}
              className="rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] p-2"
            >
              <div className="flex items-center justify-between gap-3 text-2xs font-semibold uppercase tracking-[0.14em]">
                <span className={KIND_COLOR[e.kind] || "text-[var(--color-text-secondary)]"}>
                  {e.kind}
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

      {ruledOut && (ruledOut.reasoning || ruledOut.snippet) && (
        <div className="mt-3 border-l-2 border-[var(--color-status-ok-border)] pl-3">
          <h4 className="mb-1 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-status-ok)]">
            Mitigation found
          </h4>
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

      {hasMetadata && (
        <p className="mt-3 text-2xs tabular-nums text-[var(--color-text-secondary)]">
          {metadata?.model && (
            <>
              Model: <span className="font-mono">{metadata.model}</span>
            </>
          )}
          {(metadata?.tokens_in || metadata?.tokens_out) && (
            <>
              {metadata?.model ? " · " : ""}
              {(metadata?.tokens_in ?? 0).toLocaleString()} in /{" "}
              {(metadata?.tokens_out ?? 0).toLocaleString()} out
            </>
          )}
        </p>
      )}
    </section>
  )
}
