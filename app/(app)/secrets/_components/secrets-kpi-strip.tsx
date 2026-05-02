import type { SecretFinding, SecretsTrendEntry } from "@/lib/shared/secrets/types"

function median(values: number[]) {
  if (values.length === 0) return null
  const sorted = [...values].sort((a, b) => a - b)
  const middle = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 0 ? Math.round((sorted[middle - 1] + sorted[middle]) / 2) : sorted[middle]
}

function ageInDays(value: string | null | undefined) {
  if (!value) return null
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return null
  return Math.max(0, Math.floor((Date.now() - parsed.getTime()) / 86_400_000))
}

export function SecretsKpiStrip({ trend, findings }: { trend: SecretsTrendEntry[]; findings: SecretFinding[] }) {
  const latest = trend.at(-1)
  const previous = trend.at(-2)

  const unresolvedExposure = latest?.endOfMonth.unresolved ?? 0
  const netChange = (latest?.endOfMonth.unresolved ?? 0) - (previous?.endOfMonth.unresolved ?? 0)
  const medianAge = median(
    findings
      .filter((finding) => finding.reviewStatus === "confirmed")
      .map((finding) => ageInDays(finding.detectedAt))
      .filter((value): value is number => value !== null),
  )

  const cards = [
    {
      label: "Current unresolved exposure",
      value: String(unresolvedExposure),
      support: unresolvedExposure === 0 ? "No open backlog right now" : "Open secrets still requiring action",
    },
    {
      label: "Net backlog change this period",
      value: `${netChange > 0 ? "+" : ""}${netChange}`,
      support: netChange > 0 ? "Backlog grew this period" : netChange < 0 ? "Backlog shrank this period" : "Backlog stayed flat",
    },
    {
      label: "Median age of unresolved confirmed findings",
      value: medianAge === null ? "n/a" : `${medianAge}d`,
      support: medianAge === null ? "No confirmed unresolved findings" : "Older median age suggests slower remediation",
    },
  ]

  return (
    <div className="grid gap-4 md:grid-cols-3">
      {cards.map((card) => (
        <div key={card.label} className="rounded-3xl border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-4 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
          <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            {card.label}
          </p>
          <p className="mt-3 text-4xl font-semibold leading-none text-[var(--color-text-primary)]">{card.value}</p>
          <p className="mt-2 text-sm text-[var(--color-text-secondary)]">{card.support}</p>
        </div>
      ))}
    </div>
  )
}
