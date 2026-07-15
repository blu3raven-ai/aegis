"use client"

import type React from "react"

import { VerdictBadge } from "@/components/shared/findings/VerdictBadge"
import { ImpactCallout } from "@/components/shared/findings/EvidenceSection"
import type { Verdict } from "@/lib/shared/findings/verdicts"
import { verdictRationale } from "@/lib/shared/findings/verdict-rationale"
import type {
  VerificationEvidence,
  VerificationEvidenceKind,
  VerificationMetadata,
} from "@/lib/shared/findings/row-mapper"

/**
 * The finding drawer's body as an advisory report: one block per report section
 * (Summary, Technical Detail, Attack Scenario, Impact, Distinctness, Notes), each
 * ALWAYS rendered with an empty state when its data is absent — so an unverified
 * finding still shows the full report skeleton with "verify to generate" prompts.
 */

const KIND_COLOR: Record<VerificationEvidenceKind, string> = {
  source: "text-[var(--color-severity-medium-text)]",
  sink: "text-[var(--color-severity-critical-text)]",
  gate: "text-[var(--color-status-ok-text)]",
}

const evidenceRefId = (n: number) => `finding-evidence-r${n}`

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

/** Section shell: a report heading that is always present, with the body or a
 *  muted empty state below it. */
function ReportSection({
  title,
  present,
  empty,
  children,
}: {
  title: string
  present: boolean
  empty: string
  children?: React.ReactNode
}) {
  return (
    <section className="space-y-2">
      <h3 className="text-base font-semibold text-[var(--color-text-primary)]">{title}</h3>
      {present ? (
        children
      ) : (
        <p className="text-sm leading-relaxed text-[var(--color-text-tertiary)]">{empty}</p>
      )}
    </section>
  )
}

export function SummarySection({ chain, refCount }: { chain?: string; refCount: number }) {
  const value = chain?.trim()
  return (
    <ReportSection
      title="Summary"
      present={Boolean(value)}
      empty="Not verified yet — run verification to summarize the exploit path."
    >
      <p className="text-sm leading-relaxed text-[var(--color-text-primary)]">
        {value ? renderChainWithRefs(value, refCount) : null}
      </p>
    </ReportSection>
  )
}

export function TechnicalDetailSection({
  evidence,
}: {
  evidence?: VerificationEvidence[] | null
}) {
  const items = evidence ?? []
  return (
    <ReportSection
      title="Technical Detail"
      present={items.length > 0}
      empty="No cited evidence yet — verify to collect the source, sink, and gate lines."
    >
      <ul className="space-y-2">
        {items.map((e, i) => (
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
                <span className={KIND_COLOR[e.kind] || "text-[var(--color-text-secondary)]"}>{e.kind}</span>
              </span>
              <span className="truncate text-[var(--color-text-secondary)]" title={`${e.file}:${e.line}`}>
                {e.file}:{e.line}
              </span>
            </div>
            <pre className="mt-1 whitespace-pre-wrap break-all rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-2 font-mono text-xs leading-relaxed">
              {e.snippet}
            </pre>
          </li>
        ))}
      </ul>
    </ReportSection>
  )
}

export function AttackScenarioSection({
  reproduction,
  attackPaths,
  refCount,
}: {
  reproduction?: string
  attackPaths?: { name?: string; steps: string }[]
  refCount: number
}) {
  const repro = reproduction?.trim()
  const paths = (attackPaths ?? []).filter((p) => p?.steps?.trim())
  return (
    <ReportSection
      title="Attack Scenario"
      present={Boolean(repro) || paths.length > 0}
      empty="No attack scenario yet — verify this finding to generate one."
    >
      <div className="space-y-3">
        {repro ? (
          <pre className="whitespace-pre-wrap break-words rounded border border-[var(--color-border)] bg-[var(--color-surface)] p-2 font-mono text-xs leading-relaxed text-[var(--color-text-primary)]">
            {repro}
          </pre>
        ) : null}
        {paths.map((p, i) => (
          <div key={i} className="rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] p-2">
            {p.name ? (
              <p className="mb-1 text-xs font-semibold text-[var(--color-text-primary)]">{p.name}</p>
            ) : null}
            <p className="text-sm leading-relaxed text-[var(--color-text-secondary)]">
              {renderChainWithRefs(p.steps, refCount)}
            </p>
          </div>
        ))}
      </div>
    </ReportSection>
  )
}

export function ImpactSection({ impact }: { impact?: string }) {
  const value = impact?.trim()
  return (
    <ReportSection
      title="Impact"
      present={Boolean(value)}
      empty="No impact statement yet — verify this finding to generate one."
    >
      {value ? <ImpactCallout>{value}</ImpactCallout> : null}
    </ReportSection>
  )
}

export function DistinctnessSection({ distinctness }: { distinctness?: string }) {
  const value = distinctness?.trim()
  return (
    <ReportSection
      title="Distinctness"
      present={Boolean(value)}
      empty="None noted."
    >
      <p className="text-sm leading-relaxed text-[var(--color-text-secondary)]">{value}</p>
    </ReportSection>
  )
}

// Supplementary context — render only when the verifier supplied it, rather than
// an always-visible empty state (these calibrate a confirmed finding, they aren't
// core report structure).

export function MitigatingFactorsSection({ factors }: { factors?: string[] }) {
  const items = (factors ?? []).map((f) => f?.trim()).filter(Boolean) as string[]
  if (items.length === 0) return null
  return (
    <section className="space-y-2">
      <h3 className="text-base font-semibold text-[var(--color-text-primary)]">Mitigating factors</h3>
      <ul className="list-disc space-y-1 pl-5 text-sm leading-relaxed text-[var(--color-text-secondary)]">
        {items.map((f, i) => (
          <li key={i}>{f}</li>
        ))}
      </ul>
    </section>
  )
}

export function RemediationStepsSection({ steps }: { steps?: string[] }) {
  const items = (steps ?? []).map((s) => s?.trim()).filter(Boolean) as string[]
  if (items.length === 0) return null
  return (
    <section className="space-y-2">
      <h3 className="text-base font-semibold text-[var(--color-text-primary)]">Defense in depth</h3>
      <ol className="list-decimal space-y-1 pl-5 text-sm leading-relaxed text-[var(--color-text-secondary)]">
        {items.map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ol>
    </section>
  )
}

export function NotesVerificationSection({
  verdict,
  metadata,
}: {
  verdict?: Verdict
  metadata?: VerificationMetadata | null
}) {
  const rationale = verdictRationale(verdict, metadata)
  const ruledOut = metadata?.ruled_out_reason
  const tokens =
    metadata?.tokens_in || metadata?.tokens_out
      ? `${(metadata.tokens_in ?? 0).toLocaleString()} in / ${(metadata.tokens_out ?? 0).toLocaleString()} out`
      : null
  const present = Boolean(verdict || rationale || metadata?.model || ruledOut)

  return (
    <ReportSection title="Notes / Verification" present={present} empty="Not verified yet.">
      <div className="space-y-2">
        {verdict ? <VerdictBadge verdict={verdict} /> : null}
        {rationale ? (
          <p className="text-sm leading-relaxed text-[var(--color-text-secondary)]">{rationale.text}</p>
        ) : null}
        {ruledOut?.source === "accepted_risk" && ruledOut.statement ? (
          <p className="text-sm leading-relaxed text-[var(--color-text-tertiary)]">
            Ruled out — accepted risk: {ruledOut.statement}
          </p>
        ) : ruledOut && (ruledOut.reasoning || ruledOut.snippet) ? (
          <div className="border-l-2 border-[var(--color-status-ok-border)] pl-3">
            <p className="mb-1 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-status-ok-text)]">
              Mitigation found
            </p>
            {ruledOut.reasoning ? <p className="text-sm leading-relaxed">{ruledOut.reasoning}</p> : null}
          </div>
        ) : null}
        {metadata?.runtime_question ? (
          <p className="text-sm leading-relaxed text-[var(--color-text-tertiary)]">
            Needs runtime check: {metadata.runtime_question}
          </p>
        ) : null}
        {metadata?.carve_out_source === "baseline" ? (
          <p className="text-sm leading-relaxed text-[var(--color-text-tertiary)]">
            Downgraded — matches baseline: {metadata.carve_out_ref}
          </p>
        ) : null}
        {metadata?.model ? (
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-2xs tabular-nums text-[var(--color-text-secondary)]">
            <span className="font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              Verified by
            </span>
            <span className="font-mono text-[var(--color-text-primary)]">{metadata.model}</span>
            {tokens ? <span>· {tokens}</span> : null}
          </div>
        ) : null}
      </div>
    </ReportSection>
  )
}
