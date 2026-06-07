"use client"

import Link from "next/link"
import { useEffect, useState } from "react"
import { PageHeader } from "@/components/layout/PageHeader"
import { SbomIcon } from "@/lib/shared/ui/page-icons"
import { listRepos, type RepoSummary } from "@/lib/client/repos-api"
import { relativeTime } from "@/lib/shared/relative-time"
import { EmptySbomState } from "@/components/shared/sbom/EmptySbomState"

function RepoCard({ repo }: { repo: RepoSummary }) {
  const totalFindings = Object.values(repo.findings_count_by_severity).reduce(
    (a, b) => a + b,
    0,
  )
  const lastScanned = repo.last_scanned_at
    ? relativeTime(repo.last_scanned_at)
    : null

  return (
    <Link
      href={`/sbom/${encodeURIComponent(repo.repo_id)}`}
      className="group flex flex-col gap-3 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5 shadow-[var(--shadow-card)] transition-colors hover:border-[var(--color-accent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 flex-col gap-1">
          <h2 className="font-[family-name:var(--font-jetbrains-mono)] text-[13px] font-semibold text-[var(--color-text-primary)] truncate">
            {repo.repo}
          </h2>
          <p className="text-[11px] text-[var(--color-text-tertiary)]">{repo.org}</p>
        </div>

        <svg
          className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-text-tertiary)] transition-colors group-hover:text-[var(--color-accent)]"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3" />
        </svg>
      </div>

      <div className="flex items-center justify-between text-[11px]">
        <span className="flex items-center gap-1.5 text-[var(--color-text-secondary)]">
          <svg className="h-3 w-3 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
            <path d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 0 1 0 3.75H5.625a1.875 1.875 0 0 1 0-3.75Z" />
          </svg>
          <strong className="font-semibold tabular-nums text-[var(--color-text-primary)]">
            {totalFindings.toLocaleString()}
          </strong>{" "}
          findings
        </span>
        <span className="text-[var(--color-text-tertiary)]">
          {lastScanned ? `Updated ${lastScanned}` : "Never scanned"}
        </span>
      </div>
    </Link>
  )
}

export default function SbomIndexPage() {
  const [repos, setRepos] = useState<RepoSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const result = await listRepos({ limit: 200 })
      setRepos(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load repositories")
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  return (
    <div className="flex h-full flex-col overflow-y-auto bg-[var(--color-bg)]">
      <PageHeader
        icon={<SbomIcon />}
        title="SBOM Browser"
        description="Browse and export Software Bills of Materials for your repositories."
      />

      {/* Repo grid */}
      <div className="mx-auto w-full max-w-5xl flex-1 px-5 py-6">
        <div className="mb-4 flex items-center justify-between">
          <p className="text-xs text-[var(--color-text-secondary)]">
            {repos.length} repositories with SBOMs
          </p>
          <Link
            href="/sbom/diff"
            className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1 text-xs text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-accent)] hover:text-[var(--color-text-primary)]"
          >
            <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
              <path d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" />
            </svg>
            Compare manifests
          </Link>
        </div>

        {error && (
          <div className="mb-6 flex items-center justify-between gap-3 rounded-xl border border-[var(--color-status-critical)]/30 bg-[var(--color-status-critical)]/5 px-4 py-3">
            <p className="text-sm text-[var(--color-status-critical)]">{error}</p>
            <button
              type="button"
              onClick={() => void load()}
              className="shrink-0 rounded-md border border-[var(--color-status-critical)]/40 px-3 py-1 text-xs text-[var(--color-status-critical)] transition-colors hover:bg-[var(--color-status-critical)]/10"
            >
              Retry
            </button>
          </div>
        )}

        {loading && repos.length === 0 ? (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3" aria-hidden="true">
            {Array.from({ length: 6 }).map((_, i) => (
              <div
                key={i}
                className="h-[88px] rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] motion-safe:animate-pulse"
              />
            ))}
          </div>
        ) : !loading && !error && repos.length === 0 ? (
          <EmptySbomState />
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {repos.map((r) => (
              <RepoCard key={r.repo_id} repo={r} />
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
