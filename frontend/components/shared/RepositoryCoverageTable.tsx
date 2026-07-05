import { InsightCard } from "@/components/shared/InsightCard"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"
import { getActiveTimeZone } from "@/lib/client/active-timezone"

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
        <Table className="min-w-full">
          <Thead>
            <Tr>
              <Th className="px-5">Repository</Th>
              <Th className="px-5">Last Updated</Th>
              <Th className="px-5 text-right">Alerts</Th>
            </Tr>
          </Thead>
          <Tbody>
            {repos.length > 0 ? (
              repos.map((repo) => (
                <Tr key={repo.fullName} interactive>
                  <Td className="px-5 py-4 font-medium text-[var(--color-text-primary)]">
                    {repo.name}
                    <span className="ml-2 text-xs font-normal text-[var(--color-text-secondary)]">{repo.fullName}</span>
                  </Td>
                  <Td className="px-5 py-4 text-[var(--color-text-secondary)]">
                    {repo.lastUpdatedAt
                      ? new Date(repo.lastUpdatedAt).toLocaleDateString(undefined, {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                          timeZone: getActiveTimeZone(),
                        })
                      : "—"}
                  </Td>
                  <Td className="px-5 py-4 text-right tabular-nums font-semibold text-[var(--color-text-primary)]">
                    {repo.alertCount}
                  </Td>
                </Tr>
              ))
            ) : (
              <Tr>
                <Td colSpan={3} className="px-5 py-6 text-center text-sm text-[var(--color-text-secondary)]">
                  {emptyMessage}
                </Td>
              </Tr>
            )}
          </Tbody>
        </Table>
      </div>
    </InsightCard>
  )
}
