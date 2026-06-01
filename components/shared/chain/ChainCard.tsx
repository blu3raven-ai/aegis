"use client"

import Link from "next/link"
import { ChainBadge } from "./ChainBadge"

interface ChainStep {
  label: string
  detail?: string
}

interface ChainCardProps {
  chainId: string
  chainType: string
  severity: string
  stepCount: number
  steps?: ChainStep[]
  /** Show as newly-arrived with shimmer badge */
  isNew?: boolean
}

/**
 * Summary card for a chain, used in the finding detail drawer.
 *
 * Purple-tinted surface using --color-state-dismissed token family.
 */
export function ChainCard({ chainId, chainType, severity, stepCount, steps, isNew }: ChainCardProps) {
  const sevColor =
    severity === "critical"
      ? "var(--color-severity-critical)"
      : severity === "high"
        ? "var(--color-severity-high)"
        : severity === "medium"
          ? "var(--color-severity-medium)"
          : "var(--color-severity-low)"

  return (
    <div className="rounded-xl border border-[var(--color-state-dismissed-border)] bg-[var(--color-state-dismissed-subtle)] p-4">
      <div className="flex items-center gap-2">
        <ChainBadge chainType={chainType} variant={isNew ? "new" : "default"} size="md" />
        <span
          className="ml-auto text-[11px] font-semibold uppercase tracking-wide"
          style={{ color: sevColor }}
        >
          {severity}
        </span>
      </div>

      <p className="mt-1.5 text-[11px] text-[var(--color-text-secondary)]">
        {stepCount} node{stepCount !== 1 ? "s" : ""} in attack path
      </p>

      {steps && steps.length > 0 && (
        <ol className="mt-3 flex flex-col gap-1.5">
          {steps.map((step, i) => (
            <li key={i}>
              {i > 0 && (
                <div
                  className="ml-[9px] my-0.5 text-[11px] leading-none text-[var(--color-text-tertiary)]"
                  aria-hidden="true"
                >
                  ↓
                </div>
              )}
              <div className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
                <span
                  className="inline-flex h-[19px] w-[19px] shrink-0 items-center justify-center rounded-full border border-[var(--color-border)] bg-[var(--color-bg-section)] text-2xs font-semibold text-[var(--color-text-primary)]"
                >
                  {i + 1}
                </span>
                <span className="font-medium text-[var(--color-text-primary)]">{step.label}</span>
                {step.detail && (
                  <span className="text-[var(--color-text-tertiary)] truncate font-[family-name:var(--font-jetbrains-mono)] text-[10.5px]">
                    {step.detail}
                  </span>
                )}
              </div>
            </li>
          ))}
        </ol>
      )}

      <Link
        href={`/chains/${chainId}`}
        className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-[var(--color-accent)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
      >
        View chain graph
        <svg className="h-3 w-3" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M3 8h10M9 4l4 4-4 4" />
        </svg>
      </Link>
    </div>
  )
}
