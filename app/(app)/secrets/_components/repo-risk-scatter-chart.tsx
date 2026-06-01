import type { SecretFinding } from "@/lib/shared/secrets/types"

function riskScore(finding: SecretFinding) {
  let score = 5
  if (finding.reviewStatus === "confirmed") score += 10
  if (finding.detector.toLowerCase().includes("aws") || finding.detector.toLowerCase().includes("cloud")) score += 15
  return score
}

export function RepoRiskScatterChart({ findings, onSelectRepository }: { findings: SecretFinding[]; onSelectRepository: (repo: string) => void }) {
  const active = findings.filter((finding) => finding.reviewStatus === "new" || finding.reviewStatus === "confirmed")
  if (active.length === 0) {
    return <div className="rounded-2xl border border-dashed border-[var(--color-border)] p-6 text-sm text-[var(--color-text-secondary)]">No findings to display.</div>
  }

  const repos = new Map<string, { count: number; score: number }>()
  for (const finding of active) {
    const data = repos.get(finding.repository) ?? { count: 0, score: 0 }
    data.count += 1
    data.score += riskScore(finding)
    repos.set(finding.repository, data)
  }

  const sorted = Array.from(repos.entries())
    .map(([name, data]) => ({ name, ...data }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 20)

  const maxCount = Math.max(...sorted.map((r) => r.count))
  const maxScore = Math.max(...sorted.map((r) => r.score))

  return (
    <div className="relative h-64 w-full">
      <div className="absolute inset-0 flex items-end justify-between border-b border-l border-[var(--color-border)] pb-2 pl-2">
        {sorted.map((repo) => (
          <button
            key={repo.name}
            type="button"
            onClick={() => onSelectRepository(repo.name)}
            title={`${repo.name}: ${repo.count} findings, risk ${repo.score}`}
            className="group relative rounded-full bg-[var(--color-accent-subtle)] ring-1 ring-[var(--color-accent-border)] transition-all hover:bg-[var(--color-accent)] hover:ring-[var(--color-accent)]"
            style={{
              left: `${(repo.count / maxCount) * 80 + 10}%`,
              bottom: `${(repo.score / maxScore) * 80 + 10}%`,
              width: `${Math.max(8, (repo.score / maxScore) * 24)}px`,
              height: `${Math.max(8, (repo.score / maxScore) * 24)}px`,
              position: "absolute",
            }}
          >
            <span className="absolute bottom-full left-1/2 mb-2 hidden -translate-x-1/2 whitespace-nowrap rounded bg-[var(--color-surface-raised)] px-2 py-1 text-2xs text-[var(--color-text-primary)] shadow-lg ring-1 ring-[var(--color-border)] group-hover:block">
              {repo.name}
            </span>
          </button>
        ))}
      </div>
      <div className="absolute bottom-0 left-0 -translate-x-1/2 translate-y-full pt-2 text-2xs text-[var(--color-text-secondary)]">Volume</div>
      <div className="absolute left-0 top-0 -translate-x-full -translate-y-1/2 rotate-[-90deg] pr-2 text-2xs text-[var(--color-text-secondary)]">Risk</div>
    </div>
  )
}
