import type { SecretFinding } from "@/lib/shared/secrets/types"
import { secretCategory } from "@/lib/shared/secrets/dashboard-utils"

export function OrgSecretHeatmap({
  findings,
  onSelectCell,
}: {
  findings: SecretFinding[]
  onSelectCell?: (org: string, detectors: string[]) => void
}) {
  const active = findings.filter((finding) => finding.reviewStatus === "new" || finding.reviewStatus === "confirmed")
  if (active.length === 0) {
    return <div className="rounded-2xl border border-dashed border-[var(--color-border)] p-6 text-sm text-[var(--color-text-secondary)]">No findings to display.</div>
  }

  const orgs = Array.from(new Set(active.map((finding) => finding.organization))).sort((a, b) => a.localeCompare(b))
  const categories = Array.from(new Set(active.map((finding) => secretCategory(finding.detector)))).sort((a, b) => a.localeCompare(b))
  const counts = new Map<string, number>()
  const detectorsByCell = new Map<string, Set<string>>()
  for (const finding of active) {
    const key = `${finding.organization}::${secretCategory(finding.detector)}`
    counts.set(key, (counts.get(key) ?? 0) + 1)
    const detSet = detectorsByCell.get(key) ?? new Set<string>()
    detSet.add(finding.detector)
    detectorsByCell.set(key, detSet)
  }

  const maxCount = Math.max(1, ...Array.from(counts.values()))

  function cellStyle(count: number) {
    if (count === 0) return { backgroundColor: "transparent" }
    const intensity = Math.sqrt(count / maxCount)
    return { backgroundColor: `rgb(from var(--color-severity-high) r g b / ${0.12 + intensity * 0.68})` }
  }

  const orgTotals = new Map<string, number>()
  for (const org of orgs) {
    const total = categories.reduce((s, c) => s + (counts.get(`${org}::${c}`) ?? 0), 0)
    orgTotals.set(org, total)
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr>
            <th className="w-36 pb-3 text-left text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
              Organization
            </th>
            {categories.map((category) => (
              <th key={category} className="pb-3 text-center text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
                {category}
              </th>
            ))}
            <th className="pb-3 pl-4 text-right text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
              Total
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--color-border)]">
          {orgs.map((org) => (
            <tr key={org}>
              <td className="py-2 pr-4 max-w-[9rem] truncate font-medium text-[var(--color-text-primary)]" title={org}>
                {org}
              </td>
              {categories.map((category) => {
                const cellKey = `${org}::${category}`
                const count = counts.get(cellKey) ?? 0
                const detectors = Array.from(detectorsByCell.get(cellKey) ?? [])
                const clickable = onSelectCell && count > 0
                return (
                  <td key={category} className="py-2 px-2 text-center">
                    {clickable ? (
                      <button
                        type="button"
                        onClick={() => onSelectCell(org, detectors)}
                        title={`${count} in ${org} / ${category} — click to filter Review`}
                        className="mx-auto flex h-10 w-full max-w-[120px] items-center justify-center rounded-lg text-sm font-semibold transition-all hover:ring-2 hover:ring-white/20 hover:brightness-110"
                        style={cellStyle(count)}
                      >
                        <span className="text-white drop-shadow-sm">{count}</span>
                      </button>
                    ) : (
                      <div
                        className="mx-auto flex h-10 w-full max-w-[120px] items-center justify-center rounded-lg text-sm font-semibold"
                        style={cellStyle(count)}
                      >
                        <span className="text-[var(--color-text-secondary)] opacity-25">—</span>
                      </div>
                    )}
                  </td>
                )
              })}
              <td className="py-2 pl-4 text-right text-sm font-semibold tabular-nums text-[var(--color-text-primary)]">
                {orgTotals.get(org)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="mt-4 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-xs text-[var(--color-text-secondary)]">Low</span>
          <div className="flex h-1.5 w-24 overflow-hidden rounded-full">
            {[0.12, 0.28, 0.44, 0.60, 0.80].map((opacity) => (
              <div key={opacity} className="flex-1" style={{ backgroundColor: `rgb(from var(--color-severity-high) r g b / ${opacity})` }} />
            ))}
          </div>
          <span className="text-xs text-[var(--color-text-secondary)]">High</span>
        </div>
        {onSelectCell && (
          <span className="text-xs text-[var(--color-text-secondary)] opacity-60">
            Click a cell to filter Review by org + key type
          </span>
        )}
      </div>
    </div>
  )
}
