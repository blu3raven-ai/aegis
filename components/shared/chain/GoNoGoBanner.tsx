"use client"

import { EnterpriseGate } from "@/components/shared/EnterpriseGate"

type Verdict = "risk" | "safe" | "uncertain" | "neutral"

interface GoNoGoBannerProps {
  verdict: Verdict
  title: string
  description: string
  /** When false, renders an EnterpriseGate instead of the actual banner */
  isEnterprise: boolean
}

const VERDICT_CONFIG: Record<
  Verdict,
  { icon: string; colorVar: string; subtleVar: string; borderVar: string }
> = {
  risk: {
    icon: "✗",
    colorVar: "var(--color-verdict-risk)",
    subtleVar: "var(--color-verdict-risk-subtle)",
    borderVar: "var(--color-verdict-risk-border)",
  },
  safe: {
    icon: "✓",
    colorVar: "var(--color-verdict-safe)",
    subtleVar: "var(--color-verdict-safe-subtle)",
    borderVar: "var(--color-verdict-safe-border)",
  },
  uncertain: {
    icon: "?",
    colorVar: "var(--color-verdict-uncertain)",
    subtleVar: "var(--color-verdict-uncertain-subtle,rgba(245,158,11,0.10))",
    borderVar: "var(--color-verdict-uncertain-border)",
  },
  neutral: {
    icon: "·",
    colorVar: "var(--color-verdict-neutral)",
    subtleVar: "var(--color-verdict-neutral-subtle)",
    borderVar: "var(--color-verdict-neutral-border)",
  },
}

/**
 * Verdict panel shown at the top of the chain detail drawer.
 *
 * Gated behind EnterpriseGate — only Argus enterprise customers see the real
 * verdict. All colours use existing --color-verdict-* tokens.
 */
export function GoNoGoBanner({ verdict, title, description, isEnterprise }: GoNoGoBannerProps) {
  if (!isEnterprise) {
    return (
      <EnterpriseGate
        feature="Go/No-Go Verdict"
        description="Chain-level deployment verdicts powered by Argus require an Enterprise license."
      />
    )
  }

  const cfg = VERDICT_CONFIG[verdict]

  return (
    <div
      className="mx-5 mt-4 flex items-center gap-3 rounded-xl border p-3.5"
      style={{
        background: cfg.subtleVar,
        borderColor: cfg.borderVar,
      }}
    >
      <div
        className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-[9px] text-lg font-bold"
        style={{
          background: `color-mix(in srgb, ${cfg.colorVar} 18%, transparent)`,
          color: cfg.colorVar,
        }}
      >
        {cfg.icon}
      </div>
      <div>
        <strong
          className="block text-[13px] font-semibold uppercase tracking-wide"
          style={{ color: cfg.colorVar }}
        >
          {title}
        </strong>
        <p className="mt-0.5 text-[12px] text-[var(--color-text-secondary)]">{description}</p>
      </div>
    </div>
  )
}
