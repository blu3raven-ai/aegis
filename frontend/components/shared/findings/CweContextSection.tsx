"use client"

import { cweInfo, type CweLikelihood } from "@/lib/shared/findings/cwe-catalog"

const LIKELIHOOD_TONE: Record<CweLikelihood, string> = {
  High: "border-[color-mix(in_srgb,var(--color-severity-critical)_40%,transparent)] bg-[color-mix(in_srgb,var(--color-severity-critical)_12%,transparent)] text-[var(--color-severity-critical-text)]",
  Medium:
    "border-[color-mix(in_srgb,var(--color-severity-high)_40%,transparent)] bg-[color-mix(in_srgb,var(--color-severity-high)_12%,transparent)] text-[var(--color-severity-high-text)]",
  Low: "border-[var(--color-border)] bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]",
}

/**
 * Inline explanation of a finding's weakness class — the CWE name, MITRE's
 * exploit-likelihood rating (when known), and a one-line description — so an
 * analyst can judge the bug class without leaving for cwe.mitre.org. Renders
 * nothing for findings whose CWE isn't in the curated catalog.
 */
export function CweContextSection({ cwe }: { cwe: string | undefined }) {
  const info = cweInfo(cwe)
  if (!info) return null

  const id = (cwe ?? "").toUpperCase()
  const num = id.replace(/^CWE-/, "")

  return (
    <section>
      <h3 className="mb-2 text-base font-semibold text-[var(--color-text-primary)]">
        Weakness
      </h3>
      <div className="rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] p-3">
        <div className="flex flex-wrap items-center gap-2">
          <a
            href={`https://cwe.mitre.org/data/definitions/${num}.html`}
            target="_blank"
            rel="noreferrer noopener"
            className="font-mono text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-accent)]"
          >
            {id}
          </a>
          <span className="text-sm font-semibold text-[var(--color-text-primary)]">
            {info.name}
          </span>
          {info.likelihood && (
            <span
              className={`ml-auto inline-flex items-center rounded-md border px-2 py-0.5 text-2xs font-semibold uppercase tracking-[0.1em] ${LIKELIHOOD_TONE[info.likelihood]}`}
              title="MITRE likelihood of exploit"
            >
              {info.likelihood} likelihood
            </span>
          )}
        </div>
        <p className="mt-2 text-sm leading-relaxed text-[var(--color-text-primary)]">
          {info.description}
        </p>
      </div>
    </section>
  )
}
