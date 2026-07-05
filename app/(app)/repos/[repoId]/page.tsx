"use client"

import { useState, useEffect } from "react"
import { useParams } from "next/navigation"
import Link from "next/link"
import { RepoDetailHero } from "@/components/shared/repos/RepoDetailHero"
import { ScanHistoryTimeline } from "@/components/shared/repos/ScanHistoryTimeline"
import { RepoCoverageBadge } from "@/components/shared/repos/RepoCoverageBadge"
import { getRepo, type RepoDetail, type RepoSummary } from "@/lib/client/repos-api"

// Demo fallback so the page renders in dev without a backend.
const DEMO: RepoDetail = {
  repo_id: "example-org/payments-api",
  org: "example-org",
  repo: "payments-api",
  last_scanned_sha: "a1b2c3d",
  manifest_set_hash: "e4f5a6b7",
  last_scanned_at: new Date(Date.now() - 2 * 60_000).toISOString(),
  findings_count_by_severity: { critical: 4, high: 2, medium: 1, low: 0 },
  chains_count: 3,
  scanners_with_coverage: ["dependencies", "secrets"],
  coverage_status: "fresh",
  scan_history: [
    {
      scan_id: "run-01",
      scanner_type: "dependencies",
      status: "completed",
      started_at: new Date(Date.now() - 2 * 60_000).toISOString(),
      duration_ms: 48_000,
      findings_count: 4,
    },
    {
      scan_id: "run-02",
      scanner_type: "secrets",
      status: "completed",
      started_at: new Date(Date.now() - 3 * 60_000).toISOString(),
      duration_ms: 12_000,
      findings_count: 2,
    },
  ],
  active_findings: [],
  attached_chains: [
    { id: "chain-01", chain_type: "RCE-reachable", severity: "critical", status: "open", created_at: new Date().toISOString() },
  ],
}

type Tab = "overview" | "findings" | "chains" | "scans"

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "chains",   label: "Chains" },
  { id: "scans",    label: "Scans" },
]

const SEV_COLORS: Record<string, string> = {
  critical: "text-[var(--color-severity-critical)]",
  high:     "text-[var(--color-severity-high)]",
  medium:   "text-[var(--color-severity-medium)]",
  low:      "text-[var(--color-text-secondary)]",
}

export default function RepoDetailPage() {
  const params = useParams<{ repoId: string }>()
  const repoId = decodeURIComponent(params.repoId ?? "")

  const [repo, setRepo] = useState<RepoDetail>(DEMO)
  const [tab, setTab] = useState<Tab>("overview")
  const [loading, setLoading] = useState(false)
  const [notFound, setNotFound] = useState(false)

  useEffect(() => {
    if (!repoId) return
    setLoading(true)
    getRepo(repoId)
      .then((data) => {
        if (data) setRepo(data)
        else setNotFound(true)
      })
      .catch(() => {
        // Backend unavailable — keep demo
      })
      .finally(() => setLoading(false))
  }, [repoId])

  if (notFound) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 p-10 text-center">
        <p className="text-lg font-semibold text-[var(--color-text-primary)]">Repo not found</p>
        <p className="text-sm text-[var(--color-text-secondary)]">{repoId} is not monitored by Aegis.</p>
        <Link href="/repos" className="text-sm text-[var(--color-accent)] hover:underline">
          Back to Repositories
        </Link>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6 p-6">
      {/* Breadcrumb */}
      <nav className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
        <Link href="/repos" className="hover:text-[var(--color-accent)] transition-colors">
          Repositories
        </Link>
        <span>/</span>
        <span className="text-[var(--color-text-primary)]">{repo.repo}</span>
      </nav>

      {/* Hero */}
      <RepoDetailHero repo={repo} />

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[var(--color-border)]">
        {TABS.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
              tab === id
                ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
                : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "overview" && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {/* Scanner coverage card */}
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
            <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.15em] text-[var(--color-text-secondary)]">
              Scanner Coverage
            </h2>
            <div className="flex flex-col gap-2">
              {[
                { key: "dependencies",        label: "Dependencies (SCA)" },
                { key: "code_scanning",        label: "SAST" },
                { key: "container_scanning",   label: "Containers" },
                { key: "secrets",              label: "Secrets" },
              ].map(({ key, label }) => {
                const covered = repo.scanners_with_coverage.includes(key)
                return (
                  <div key={key} className="flex items-center justify-between">
                    <span className="text-sm text-[var(--color-text-primary)]">{label}</span>
                    <RepoCoverageBadge status={covered ? repo.coverage_status : "never"} />
                  </div>
                )
              })}
            </div>
          </div>

          {/* Attached chains */}
          <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
            <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.15em] text-[var(--color-text-secondary)]">
              Attack Chains
            </h2>
            {repo.attached_chains.length === 0 ? (
              <p className="text-sm text-[var(--color-text-secondary)]">No chains attached to this repo.</p>
            ) : (
              <div className="flex flex-col divide-y divide-[var(--color-border)]">
                {repo.attached_chains.map((chain) => (
                  <div key={chain.id} className="flex items-center justify-between py-2.5">
                    <span className="text-sm text-[var(--color-text-primary)]">{chain.chain_type}</span>
                    <span className={`text-xs font-semibold ${SEV_COLORS[chain.severity] ?? "text-[var(--color-text-secondary)]"}`}>
                      {chain.severity}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {tab === "findings" && (
        <div className="overflow-auto rounded-2xl border border-[var(--color-border)]">
          {repo.active_findings.length === 0 ? (
            <p className="py-10 text-center text-sm text-[var(--color-text-secondary)]">No open findings for this repo.</p>
          ) : (
            <table className="min-w-full divide-y divide-[var(--color-border)] text-sm">
              <thead className="bg-[var(--color-surface-raised)] text-left text-xs uppercase tracking-[0.15em] text-[var(--color-text-secondary)]">
                <tr>
                  <th className="px-5 py-3">Scanner</th>
                  <th className="px-5 py-3">Finding</th>
                  <th className="px-5 py-3">Severity</th>
                  <th className="px-5 py-3">First seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]">
                {repo.active_findings.map((f) => (
                  <tr key={f.id} className="hover:bg-[var(--color-surface-raised)]">
                    <td className="px-5 py-3.5 text-xs text-[var(--color-text-secondary)]">{f.tool}</td>
                    <td className="px-5 py-3.5 font-mono text-xs text-[var(--color-text-primary)] max-w-xs truncate">{f.identity_key}</td>
                    <td className={`px-5 py-3.5 text-xs font-semibold ${SEV_COLORS[f.severity ?? ""] ?? "text-[var(--color-text-secondary)]"}`}>
                      {f.severity ?? "—"}
                    </td>
                    <td className="px-5 py-3.5 text-xs text-[var(--color-text-secondary)]">
                      {new Date(f.first_seen_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === "chains" && (
        <div className="rounded-2xl border border-[var(--color-border)] p-5">
          {repo.attached_chains.length === 0 ? (
            <p className="py-6 text-center text-sm text-[var(--color-text-secondary)]">No attack chains for this repo.</p>
          ) : (
            <div className="flex flex-col divide-y divide-[var(--color-border)]">
              {repo.attached_chains.map((chain) => (
                <div key={chain.id} className="flex items-center justify-between py-3">
                  <div>
                    <p className="text-sm font-medium text-[var(--color-text-primary)]">{chain.chain_type}</p>
                    <p className="text-xs text-[var(--color-text-secondary)]">{chain.id}</p>
                  </div>
                  <span className={`text-xs font-semibold ${SEV_COLORS[chain.severity] ?? "text-[var(--color-text-secondary)]"}`}>
                    {chain.severity}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {tab === "scans" && (
        <ScanHistoryTimeline runs={repo.scan_history} />
      )}
    </div>
  )
}
