import { InsightCard } from "@/components/shared/InsightCard"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"

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
        <Table className="min-w-full">
          <Thead>
            <Tr>
              <Th className="px-5">Repository</Th>
              <Th className="px-5">Reason</Th>
              <Th className="px-5">Last Scanned</Th>
            </Tr>
          </Thead>
          <Tbody>
            {gaps.length > 0 ? (
              gaps.map((gap) => (
                <Tr key={`${gap.repository}:${gap.reason}`} interactive>
                  <Td className="px-5 py-4 font-medium text-[var(--color-text-primary)]">{gap.repository}</Td>
                  <Td className="px-5 py-4 text-[var(--color-text-secondary)]">{gap.reason.replaceAll("_", " ")}</Td>
                  <Td className="px-5 py-4 text-[var(--color-text-secondary)]">
                    {gap.lastScannedAt
                      ? new Date(gap.lastScannedAt).toLocaleDateString(undefined, {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })
                      : "—"}
                  </Td>
                </Tr>
              ))
            ) : (
              <Tr>
                <Td colSpan={3} className="px-5 py-6 text-center text-sm text-[var(--color-text-secondary)]">
                  No repository data yet.
                </Td>
              </Tr>
            )}
          </Tbody>
        </Table>
      </div>
    </InsightCard>
  )
}
