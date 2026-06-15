import { cn } from "@/lib/shared/utils"
import type { ScanVerificationSummary } from "@/lib/client/repos-api"

// Approximate cost — exact provider rates aren't stored yet.
const APPROX_COST_PER_1K_TOKENS = 0.01

type CellKey = "confirmed" | "needs_verify" | "possible" | "ruled_out"

const CELLS: { key: CellKey; label: string; valueClass: string }[] = [
  {
    key: "confirmed",
    label: "🔴 Confirmed",
    valueClass: "text-[var(--color-severity-critical)]",
  },
  {
    key: "needs_verify",
    label: "🟡 Needs verify",
    valueClass: "text-[var(--color-severity-medium)]",
  },
  {
    key: "possible",
    label: "⚪ Possible",
    valueClass: "text-[var(--color-text-secondary)]",
  },
  {
    key: "ruled_out",
    label: "✓ Ruled out",
    valueClass: "text-[var(--color-status-ok)]",
  },
]

interface VerificationSummaryProps {
  summary: ScanVerificationSummary
}

/** Per-scan LLM-verification KPI card for the scan detail page. */
export function VerificationSummary({ summary }: VerificationSummaryProps) {
  const totalTokens = (summary.tokens_in ?? 0) + (summary.tokens_out ?? 0)
  const totalVerified =
    summary.confirmed +
    summary.needs_verify +
    summary.possible +
    summary.ruled_out

  // No verification ran — surface a notice rather than a 0/0/0/0 KPI grid.
  if (totalTokens === 0 && totalVerified === 0 && summary.legacy > 0) {
    return (
      <div className="rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] px-5 py-3">
        <p className="text-xs italic text-[var(--color-text-secondary)]">
          This scan ran without LLM verification.
        </p>
      </div>
    )
  }

  const approxCost = (totalTokens / 1000) * APPROX_COST_PER_1K_TOKENS

  return (
    <div className="rounded border border-[var(--color-border)] bg-[var(--color-bg-section)] px-5 py-3">
      <h3 className="text-base font-semibold mb-3">Verification</h3>
      <div className="grid grid-cols-4 gap-4 lg:gap-6">
        {CELLS.map((c) => (
          <div key={c.key}>
            <div
              className={cn(
                "text-2xl font-semibold leading-none tabular-nums",
                c.valueClass,
              )}
            >
              {(summary[c.key] ?? 0).toLocaleString()}
            </div>
            <div className="mt-1 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)] whitespace-nowrap">
              {c.label}
            </div>
          </div>
        ))}
      </div>
      {totalTokens > 0 && (
        <p className="mt-3 text-xs text-[var(--color-text-secondary)]">
          {summary.model && (
            <>
              Model: <span className="font-mono">{summary.model}</span>
              {" · "}
            </>
          )}
          <span className="tabular-nums">
            {totalTokens.toLocaleString()}
          </span>{" "}
          tokens ·{" "}
          <span
            title="Approximation — actual pricing depends on your LLM provider's per-token rates."
            className="tabular-nums underline decoration-dotted underline-offset-2 cursor-help"
          >
            ~${approxCost.toFixed(3)}
          </span>
        </p>
      )}
    </div>
  )
}
