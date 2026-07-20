"use client"

/**
 * "Data flow" block for SAST taint findings — the ordered source → sink path,
 * the most decision-relevant artifact for confirming a taint is real. Renders
 * only when the finding carries a multi-step flow (a single step adds nothing
 * over the code preview).
 */

import type { CodeFlowStep } from "@/lib/shared/findings/row-mapper"

export function FindingDataFlowSection({ steps }: { steps?: CodeFlowStep[] }) {
  if (!steps || steps.length < 2) return null

  return (
    <section aria-labelledby="finding-dataflow-title">
      <h3 id="finding-dataflow-title" className="text-base font-semibold text-[var(--color-text-primary)]">
        Data flow
      </h3>
      <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
        How tainted input reaches the sink, source first.
      </p>
      <ol className="relative mt-3 space-y-2.5 before:absolute before:left-[11px] before:top-3 before:bottom-3 before:w-px before:bg-[var(--color-border-divider)]">
        {steps.map((step, i) => {
          const role = i === 0 ? "Source" : i === steps.length - 1 ? "Sink" : `Step ${i + 1}`
          return (
            <li key={i} className="relative flex gap-3">
              <span className="mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-full bg-[var(--color-surface-raised)] text-[11px] font-semibold tabular-nums text-[var(--color-text-secondary)]">
                {i + 1}
              </span>
              <div className="min-w-0">
                <div className="font-mono text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)]">
                  {role}
                </div>
                <div
                  className="truncate font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-secondary)]"
                  title={`${step.file}:${step.line}`}
                >
                  {step.file}:{step.line}
                </div>
                {step.snippet && (
                  <code
                    className="mt-0.5 block truncate font-[family-name:var(--font-jetbrains-mono)] text-[12px] text-[var(--color-text-primary)]"
                    title={step.snippet}
                  >
                    {step.snippet}
                  </code>
                )}
              </div>
            </li>
          )
        })}
      </ol>
    </section>
  )
}
