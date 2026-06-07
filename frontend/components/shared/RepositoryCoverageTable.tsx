import { InsightCard } from "@/components/shared/InsightCard"

export interface RepoCoverageRow {
  name: string
  fullName: string
  alertCount: number
  lastUpdatedAt: string | null
}

export function RepositoryCoverageTable({
  repos,
  emptyMessage = "No repository data yet.",
}: {
  repos: RepoCoverageRow[]
  emptyMessage?: string
}) {
  return (
    <InsightCard
      eyebrow="Repository Coverage"
      title="Scanned repositories"
      description="Repositories represented in the scanner feed and when they were last updated."
    >
      <div className="overflow-auto rounded-2xl border border-[var(--color-border)]">
        <table className="min-w-full divide-y divide-[var(--color-border)] text-sm">
          <thead className="bg-[var(--color-surface-raised)] text-left text-xs uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            <tr>
              <th className="px-5 py-3">Repository</th>
              <th className="px-5 py-3">Last Updated</th>
              <th className="px-5 py-3 text-right">Alerts</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--color-border)]">
            {repos.length > 0 ? (
              repos.map((repo) => (
                <tr
                  key={repo.fullName}
                  className="transition-colors hover:bg-[var(--color-surface-raised)]"
                >
                  <td className="px-5 py-4 font-medium text-[var(--color-text-primary)]">
                    {repo.name}
                    <span className="ml-2 text-xs font-normal text-[var(--color-text-secondary)]">{repo.fullName}</span>
                  </td>
                  <td className="px-5 py-4 text-[var(--color-text-secondary)]">
                    {repo.lastUpdatedAt
                      ? new Date(repo.lastUpdatedAt).toLocaleDateString(undefined, {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })
                      : "—"}
                  </td>
                  <td className="px-5 py-4 text-right tabular-nums font-semibold text-[var(--color-text-primary)]">
                    {repo.alertCount}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={3} className="px-5 py-6 text-center text-sm text-[var(--color-text-secondary)]">
                  {emptyMessage}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </InsightCard>
  )
}
