/**
 * Compact badge showing the LLM-verification verdict for a finding.
 * Returns null when no verdict is set (legacy / unverified findings).
 */
export type Verdict =
  | "confirmed"
  | "needs_verify"
  | "possible"
  | "ruled_out"
  | null
  | undefined;

type VerdictStyle = {
  label: string;
  emoji: string;
  className: string;
  title: string;
};

const STYLES: Record<NonNullable<Verdict>, VerdictStyle> = {
  confirmed: {
    label: "Confirmed",
    emoji: "🔴",
    className:
      "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]",
    title: "AI found an exploit chain and the skeptic agreed.",
  },
  needs_verify: {
    label: "Needs verify",
    emoji: "🟡",
    className:
      "bg-[var(--color-severity-medium-subtle)] text-[var(--color-severity-medium)]",
    title:
      "AI found a plausible chain but the skeptic flagged uncertainty. Human review recommended.",
  },
  possible: {
    label: "Possible",
    emoji: "⚪",
    className:
      "bg-[var(--color-bg-section)] text-[var(--color-text-secondary)]",
    title: "Low-confidence; insufficient evidence to confirm or rule out.",
  },
  ruled_out: {
    label: "Ruled out",
    emoji: "✓",
    className:
      "border border-[var(--color-status-ok-border)] bg-transparent text-[var(--color-status-ok)]",
    title: "AI found an upstream mitigation that neutralises this finding.",
  },
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  if (!verdict) return null;
  const style = STYLES[verdict];
  if (!style) return null;

  return (
    <span
      title={style.title}
      aria-label={`${style.label} verdict`}
      className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-2xs font-semibold align-middle leading-none tabular-nums whitespace-nowrap ${style.className}`}
    >
      <span aria-hidden>{style.emoji}</span>
      {style.label}
    </span>
  );
}
