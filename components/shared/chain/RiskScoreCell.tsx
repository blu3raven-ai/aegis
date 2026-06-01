"use client"

import { ArgusTag } from "./ArgusTag"

interface RiskScoreCellProps {
  score: number
  /** Show the Argus attribution pill next to the score */
  argus?: boolean
}

/**
 * Tabular risk-score cell (0-100) with optional Argus attribution.
 *
 * Renders the score in monospace for column alignment and a subtle bar
 * showing intensity. Colour derived from severity thresholds already in
 * --color-severity-* tokens — no new tokens needed.
 */
export function RiskScoreCell({ score, argus }: RiskScoreCellProps) {
  const clampedScore = Math.min(100, Math.max(0, score))

  const barColor =
    clampedScore >= 80
      ? "var(--color-severity-critical)"
      : clampedScore >= 60
        ? "var(--color-severity-high)"
        : clampedScore >= 40
          ? "var(--color-severity-medium)"
          : "var(--color-severity-low)"

  return (
    <div className="flex flex-col items-end gap-1 min-w-[3.5rem]">
      <div className="flex items-center gap-1.5">
        {argus && <ArgusTag />}
        <span className="font-[family-name:var(--font-jetbrains-mono)] text-[13px] font-medium tabular-nums text-[var(--color-text-primary)]">
          {clampedScore}
          <span className="text-[11px] font-normal text-[var(--color-text-tertiary)]">/100</span>
        </span>
      </div>
      <div
        className="h-1 w-full rounded-full border border-[var(--color-border-divider)] bg-[var(--color-bg-section)] overflow-hidden"
        aria-hidden="true"
      >
        <div
          className="h-full rounded-full"
          style={{
            width: `${clampedScore}%`,
            background: `linear-gradient(90deg, var(--color-severity-high), ${barColor})`,
          }}
        />
      </div>
    </div>
  )
}
