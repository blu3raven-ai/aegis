"use client"

interface ChainBadgeProps {
  chainType: string
  variant?: "default" | "new"
  size?: "sm" | "md"
}

/**
 * Purple pill that marks a finding or chain header.
 *
 * Uses only --color-state-dismissed tokens — no new design tokens introduced.
 * The "new" variant plays a shimmer animation to signal freshly-pushed intel.
 */
export function ChainBadge({ chainType, variant = "default", size = "sm" }: ChainBadgeProps) {
  const base =
    "inline-flex items-center gap-1 rounded-full border font-medium uppercase tracking-wide text-[var(--color-state-dismissed)] border-[var(--color-state-dismissed-border,rgba(168,85,247,0.25))] bg-[var(--color-state-dismissed-subtle,rgba(168,85,247,0.10))]"
  const sizeClass = size === "md" ? "px-2.5 py-0.5 text-[11px]" : "px-1.5 py-px text-2xs"
  const shimmer =
    variant === "new"
      ? "[background:linear-gradient(90deg,rgba(192,132,252,0.13),rgba(192,132,252,0.28),rgba(192,132,252,0.13))] [background-size:200%_100%] animate-[chain-shimmer_2.4s_ease-in-out_infinite]"
      : ""

  return (
    <span className={`${base} ${sizeClass} ${shimmer}`}>
      ✦ Chain · {chainType}
    </span>
  )
}
