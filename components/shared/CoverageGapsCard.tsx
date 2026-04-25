import { InsightCard } from "@/components/shared/InsightCard"

export interface CoverageGap {
  repository: string
  reason: string
  lastScannedAt: string | null
}

export function CoverageGapsCard({
  gaps,
}: {
  gaps: CoverageGap[]
}) {
  return (
    <InsightCard
      eyebrow="Coverage Gaps"
      title="Repositories with stale or missing coverage"
      description="Repos that haven't been scanned recently or were skipped in the latest run."
    >
      <div className="overflow-auto rounded-2xl border border-[var(--color-border)]">
        <table className="min-w-full divide-y divide-[var(--color-border)] text-sm">
          <thead className="bg-[var(--color-surface-raised)] text-left text-xs uppercase tracking-[0.18em] text-[var(--color-text-secondary)]">
            <tr>
              <th className="px-5 py-3">Repository</th>
              <th className="px-5 py-3">Reason</th>
              <th className="px-5 py-3">Last Scanned</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)]">
            {gaps.length > 0 ? (
              gaps.map((gap) => (
                <tr
                  key={`${gap.repository}:${gap.reason}`}
                  className="transition-colors hover:bg-[var(--color-surface-raised)]"
                >
                  <td className="px-5 py-4 font-medium text-[var(--color-text-primary)]">{gap.repository}</td>
                  <td className="px-5 py-4 text-[var(--color-text-secondary)]">{gap.reason.replaceAll("_", " ")}</td>
                  <td className="px-5 py-4 text-[var(--color-text-secondary)]">
                    {gap.lastScannedAt
                      ? new Date(gap.lastScannedAt).toLocaleDateString(undefined, {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })
                      : "—"}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={3} className="px-5 py-6 text-center text-sm text-[var(--color-text-secondary)]">
                  No repository data yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </InsightCard>
  )
}
