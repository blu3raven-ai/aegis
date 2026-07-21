"use client"

import type React from "react"

import { LinkButton } from "@/components/ui/LinkButton"
import { ReverifyButton } from "@/components/shared/findings/ReverifyButton"
import { ImpactCallout } from "@/components/shared/findings/EvidenceSection"
import type { Verdict } from "@/lib/shared/findings/verdicts"
import { verdictRationale } from "@/lib/shared/findings/verdict-rationale"
import type {
  VerificationEvidence,
  VerificationEvidenceKind,
  VerificationMetadata,
} from "@/lib/shared/findings/row-mapper"

/**
 * The finding drawer's advisory report, rendered as one flowing document: each
 * part (Summary, Technical Detail, Attack Scenario, Impact, Distinctness, Notes)
 * is a heading + body that appears only when the verifier supplied its data.
 * Absent parts are omitted rather than shown as skeletons, so a verified finding
 * reads as a single cohesive advisory. When nothing is verified the caller shows
 * one consolidated {@link AdvisoryUnverifiedNote} instead of a wall of prompts.
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

/** One part of the advisory document: a `##`-style heading over its body.
 *  Renders nothing when the verifier supplied no data, so the report omits
 *  empty parts rather than padding them with skeletons. */
function ReportSection({
  title,
  present,
  children,
}: {
  title: string
  present: boolean
  children?: React.ReactNode
}) {
  if (!present) return null
  return (
    <section className="space-y-2">
      <h3 className="border-b border-[var(--color-border-divider)] pb-1.5 text-base font-semibold text-[var(--color-text-primary)]">
        {title}
      </h3>
      {children}
    </section>
  )
}

/** True when the verifier supplied any of the prose advisory parts, so the
 *  drawer should render the bundled document rather than the unverified note. */
export function hasVerifiedAdvisory(f: {
  exploitChain?: string | null
  evidence?: unknown[] | null
  codeFlows?: unknown[] | null
  verificationMetadata?: VerificationMetadata | null
}): boolean {
  const vm = f.verificationMetadata
  return Boolean(
    f.exploitChain?.trim() ||
      f.evidence?.length ||
      f.codeFlows?.length ||
      vm?.reproduction?.trim() ||
      vm?.attack_paths?.length ||
      vm?.impact?.trim() ||
      vm?.mitigating_factors?.length ||
      vm?.distinctness?.trim(),
  )
}

// Structural skeletons blurred behind the call to action so the analyst sees
// there is rich content to unlock. Purely decorative: aria-hidden, inert.
function GhostAdvisory() {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <div className="h-3.5 w-40 rounded bg-[var(--color-surface-raised)]" />
        <div className="h-2.5 w-full rounded bg-[var(--color-surface-raised)]" />
        <div className="h-2.5 w-11/12 rounded bg-[var(--color-surface-raised)]" />
      </div>
      <div className="flex gap-2">
        <div className="h-5 w-20 rounded-sm bg-[color-mix(in_srgb,var(--color-severity-critical)_45%,transparent)]" />
        <div className="h-5 w-16 rounded-sm bg-[var(--color-surface-raised)]" />
        <div className="h-5 w-24 rounded-sm bg-[color-mix(in_srgb,var(--color-status-ok)_40%,transparent)]" />
      </div>
      <div className="space-y-2 rounded-md border border-[var(--color-border)] p-3">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="flex items-center gap-4">
            <div className="h-2.5 w-24 rounded bg-[var(--color-surface-raised)]" />
            <div className="h-2.5 flex-1 rounded bg-[var(--color-surface-raised)]" />
          </div>
        ))}
      </div>
    </div>
  )
}

function GhostRemediation() {
  // A ghosted unified diff: tinted add/remove lines read as "a patch lives here".
  const rows: Array<[string, string]> = [
    ["low", "w-10/12"],
    ["critical", "w-8/12"],
    ["low", "w-11/12"],
    ["neutral", "w-9/12"],
    ["low", "w-7/12"],
  ]
  const tint = (kind: string) =>
    kind === "low"
      ? "bg-[color-mix(in_srgb,var(--color-severity-low)_38%,transparent)]"
      : kind === "critical"
        ? "bg-[color-mix(in_srgb,var(--color-severity-critical)_38%,transparent)]"
        : "bg-[var(--color-surface-raised)]"
  return (
    <div className="space-y-4">
      <div className="h-3.5 w-32 rounded bg-[var(--color-surface-raised)]" />
      <div className="space-y-1.5 rounded-md border border-[var(--color-border)] p-3">
        {rows.map(([kind, w], i) => (
          <div key={i} className={`h-2.5 rounded ${w} ${tint(kind)}`} />
        ))}
      </div>
    </div>
  )
}

/** Blurred preview of verifier-generated content behind a call to action. When
 *  no model key is configured it carries the BYOK CTA; otherwise it explains the
 *  finding is queued for verification on the next scan. */
function VerificationUpsell({
  title,
  description,
  verificationEnabled,
  findingId,
  findingUpdatedAt,
  ghost,
}: {
  title: string
  description: string
  verificationEnabled: boolean
  findingId: number | string
  findingUpdatedAt?: string | null
  ghost: React.ReactNode
}) {
  return (
    <section className="relative overflow-hidden rounded-md border border-[var(--color-border)] bg-[var(--color-bg-section)]">
      <div
        aria-hidden="true"
        className="pointer-events-none select-none px-4 py-4 opacity-60 blur-[3px]"
      >
        {ghost}
      </div>
      <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-[color-mix(in_srgb,var(--color-surface)_55%,transparent)] px-6 text-center">
        <h3 className="text-sm font-semibold uppercase tracking-[0.08em] text-[var(--color-text-primary)]">
          {title}
        </h3>
        <p className="max-w-sm text-xs leading-relaxed text-[var(--color-text-secondary)]">
          {description}
        </p>
        {verificationEnabled ? (
          <div className="mt-1">
            <ReverifyButton findingId={findingId} findingUpdatedAt={findingUpdatedAt} />
          </div>
        ) : (
          <div className="mt-1 flex flex-col items-center gap-1.5">
            <LinkButton
              href="/settings#llm"
              variant="primary"
              size="sm"
              trailingIcon={<span aria-hidden="true">→</span>}
            >
              Enable LLM verification
            </LinkButton>
            <p className="text-2xs text-[var(--color-text-tertiary)]">
              Bring your own model key to unlock verified advisories.
            </p>
          </div>
        )}
      </div>
    </section>
  )
}

/** Advisory-absent empty state — a blurred advisory preview behind the CTA. */
export function AdvisoryUnverifiedNote({
  verificationEnabled = true,
  findingId,
  findingUpdatedAt,
}: {
  verificationEnabled?: boolean
  findingId: number | string
  findingUpdatedAt?: string | null
}) {
  return (
    <VerificationUpsell
      title="Advisory not generated"
      description="LLM verification produces the full advisory: exploit summary, cited technical evidence, attack scenario, impact, and remediation guidance."
      verificationEnabled={verificationEnabled}
      findingId={findingId}
      findingUpdatedAt={findingUpdatedAt}
      ghost={<GhostAdvisory />}
    />
  )
}

/** Scanner remediation text is usable only when it is a real fix, not a raw
 *  rule template (a `$UPPER` placeholder token means the scanner handed us its
 *  template, not concrete guidance). */
export function isUsableRemediation(remediation?: string): boolean {
  return remediation ? !/\$[A-Z][A-Z0-9_]*/.test(remediation) : false
}

/** Shown in place of the LLM verification upsell for secret findings. Secret
 *  material must never be sent to the verification model, so the LLM advisory /
 *  remediation / PoC surfaces are intentionally absent for these findings. */
export function SecretNoVerificationNote() {
  return (
    <section className="rounded-md border border-dashed border-[var(--color-border)] bg-[var(--color-bg-section)] px-4 py-4 text-center">
      <h3 className="text-sm font-semibold uppercase tracking-[0.08em] text-[var(--color-text-primary)]">
        LLM verification disabled
      </h3>
      <p className="mx-auto mt-1 max-w-sm text-xs leading-relaxed text-[var(--color-text-secondary)]">
        Secret findings are never sent to the verification model, so no LLM
        advisory, remediation, or proof-of-concept is generated. Rotate the
        secret and revoke any exposed credentials.
      </p>
    </section>
  )
}

/** Remediation-absent empty state — a blurred fix preview behind the CTA. */
export function RemediationUnverifiedNote({
  verificationEnabled = true,
  findingId,
  findingUpdatedAt,
}: {
  verificationEnabled?: boolean
  findingId: number | string
  findingUpdatedAt?: string | null
}) {
  return (
    <VerificationUpsell
      title="No fix generated yet"
      description="LLM verification proposes a concrete remediation: a patch or version upgrade with the steps to apply it safely."
      verificationEnabled={verificationEnabled}
      findingId={findingId}
      findingUpdatedAt={findingUpdatedAt}
      ghost={<GhostRemediation />}
    />
  )
}

/** Shown in the Remediation group when a finding was verified but the advisory
 *  came back without remediation guidance — a partial result the analyst should
 *  be able to recognize and act on rather than silently seeing an empty group. */
export function AdvisoryIncompleteNote({
  verificationEnabled = true,
  findingId,
  findingUpdatedAt,
}: {
  verificationEnabled?: boolean
  findingId: number | string
  findingUpdatedAt?: string | null
}) {
  return (
    <section className="flex flex-col items-center rounded-md border border-dashed border-[var(--color-border)] bg-[var(--color-bg-section)] px-4 py-4 text-center">
      <h3 className="text-sm font-semibold uppercase tracking-[0.08em] text-[var(--color-text-primary)]">
        Remediation guidance incomplete
      </h3>
      <p className="mt-1 max-w-sm text-sm leading-relaxed text-[var(--color-text-secondary)]">
        Verification finished without remediation steps for this finding.
      </p>
      <div className="mt-3">
        {verificationEnabled ? (
          <ReverifyButton findingId={findingId} findingUpdatedAt={findingUpdatedAt} />
        ) : (
          <LinkButton
            href="/settings#llm"
            variant="primary"
            size="sm"
            trailingIcon={<span aria-hidden="true">→</span>}
          >
            Enable LLM verification
          </LinkButton>
        )}
      </div>
    </section>
  )
}

export function SummarySection({ chain, refCount }: { chain?: string; refCount: number }) {
  const value = chain?.trim()
  return (
    <ReportSection
      title="Summary"
      present={Boolean(value)}
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
      title="Technical detail"
      present={items.length > 0}
    >
      <ul className="space-y-2">
        {items.map((e, i) => (
          <li
            key={i}
            id={evidenceRefId(i + 1)}
            className="scroll-mt-4 rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] p-2 target:ring-1 target:ring-[var(--color-accent)]"
          >
            <div className="flex items-center justify-between gap-3 text-2xs font-mono font-semibold uppercase tracking-[0.14em]">
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
      title="Attack scenario"
      present={Boolean(repro) || paths.length > 0}
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
      <h3 className="border-b border-[var(--color-border-divider)] pb-1.5 text-base font-semibold text-[var(--color-text-primary)]">Mitigating factors</h3>
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
      <h3 className="border-b border-[var(--color-border-divider)] pb-1.5 text-base font-semibold text-[var(--color-text-primary)]">Defense in depth</h3>
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
  // The verdict itself is already prominent in the overview chips, so this
  // section only earns its place when it carries real provenance: a rationale,
  // a ruled-out reason, a runtime question, or model/token usage.
  const present = Boolean(
    rationale || metadata?.model || ruledOut || metadata?.runtime_question || tokens,
  )

  return (
    <ReportSection title="Notes / Verification" present={present}>
      <div className="space-y-2">
        {rationale ? (
          <p className="text-sm leading-relaxed text-[var(--color-text-secondary)]">{rationale.text}</p>
        ) : null}
        {ruledOut?.source === "accepted_risk" && ruledOut.statement ? (
          <p className="text-sm leading-relaxed text-[var(--color-text-tertiary)]">
            Ruled out, accepted risk: {ruledOut.statement}
          </p>
        ) : ruledOut && (ruledOut.reasoning || ruledOut.snippet) ? (
          <div className="border-l-2 border-[var(--color-status-ok-border)] pl-3">
            <p className="mb-1 text-2xs font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-status-ok-text)]">
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
            Downgraded, matches baseline: {metadata.carve_out_ref}
          </p>
        ) : null}
        {metadata?.model ? (
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-2xs tabular-nums text-[var(--color-text-secondary)]">
            <span className="font-mono font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
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
