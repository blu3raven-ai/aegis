"use client"

import { useState, useEffect, useCallback, useMemo, useRef } from "react"
import { useParams, useSearchParams } from "next/navigation"
import Link from "next/link"
import { RepoDetailHero } from "@/components/shared/repos/RepoDetailHero"
import { ScanHistoryTimeline } from "@/components/shared/repos/ScanHistoryTimeline"
import { ScannerCoverageStrip } from "@/components/shared/repos/ScannerCoverageStrip"
import { PageHeader } from "@/components/layout/PageHeader"
import { getRepo, type RepoDetail } from "@/lib/client/repos-api"
import {
  getRelease,
  listReleases,
  type ReleaseDetail,
  type ReleaseSummary,
} from "@/lib/client/releases-api"
import { ReposIcon } from "@/lib/shared/ui/page-icons"
import { PreReleaseScanPanel } from "./PreReleaseScanPanel"
import { ReleaseVerdictCard } from "@/components/shared/releases/ReleaseVerdictCard"
import { BlockerDiffList } from "@/components/shared/releases/BlockerDiffList"
import { ImprovementsList } from "@/components/shared/releases/ImprovementsList"
import { RecentReleaseChecksTable } from "@/components/shared/releases/RecentReleaseChecksTable"

const DEMO: RepoDetail = {
  repo_id: "example-org/payments-api",
  org: "example-org",
  repo: "payments-api",
  last_scanned_sha: "a1b2c3d",
  manifest_set_hash: "e4f5a6b7",
  last_scanned_at: new Date(Date.now() - 2 * 60_000).toISOString(),
  findings_count_by_severity: { critical: 4, high: 2, medium: 1, low: 0 },
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
}

type Tab = "overview" | "findings" | "scans"

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "scans",    label: "Pre-release scan" },
]

const SEV_COLORS: Record<string, string> = {
  critical: "text-[var(--color-severity-critical)]",
  high:     "text-[var(--color-severity-high)]",
  medium:   "text-[var(--color-severity-medium)]",
  low:      "text-[var(--color-text-secondary)]",
}

type FindingsSubFilter = "all" | "dependencies" | "code" | "secrets" | "container"

const FINDINGS_SUB_FILTERS: { id: FindingsSubFilter; label: string }[] = [
  { id: "all",          label: "All" },
  { id: "dependencies", label: "Dependencies" },
  { id: "code",         label: "Code" },
  { id: "secrets",      label: "Secrets" },
  { id: "container",    label: "Container" },
]

function categoryForTool(tool: string): Exclude<FindingsSubFilter, "all"> | null {
  const t = tool.toLowerCase()
  if (t.includes("container") || t.includes("trivy")) return "container"
  if (t === "grype" || t === "syft" || t === "osv") return "dependencies"
  if (t === "gitleaks" || t === "trufflehog") return "secrets"
  if (t === "semgrep" || t === "joern" || t === "codeql" || t === "bandit") return "code"
  return null
}

export function RepoDetailPageContent() {
  const params = useParams<{ repoId: string }>()
  const searchParams = useSearchParams()
  const repoId = decodeURIComponent(params.repoId ?? "")
  // `?scan_id=` is the share-link deep-link to a specific pre-release scan;
  // when present, the scans tab is the only sensible landing surface.
  const deepLinkScanId = searchParams.get("scan_id")

  const [repo, setRepo] = useState<RepoDetail>(DEMO)
  const [tab, setTab] = useState<Tab>(deepLinkScanId ? "scans" : "overview")
  const [findingsFilter, setFindingsFilter] = useState<FindingsSubFilter>("all")
  const [, setLoading] = useState(false)
  const [notFound, setNotFound] = useState(false)
  const [latestRelease, setLatestRelease] = useState<ReleaseDetail | null>(null)
  const [latestReleaseLoading, setLatestReleaseLoading] = useState(false)
  const [recentReleases, setRecentReleases] = useState<ReleaseSummary[]>([])
  const [recentReleasesLoading, setRecentReleasesLoading] = useState(false)
  const releaseRequestRef = useRef(0)

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

  useEffect(() => {
    if (tab !== "scans") return
    let cancelled = false
    setRecentReleasesLoading(true)
    listReleases({ limit: 8 })
      .then((res) => { if (!cancelled) setRecentReleases(res.releases) })
      .catch(() => {})
      .finally(() => { if (!cancelled) setRecentReleasesLoading(false) })
    return () => { cancelled = true }
  }, [tab])

  const loadRelease = useCallback(async (scanId: string) => {
    const token = ++releaseRequestRef.current
    setLatestReleaseLoading(true)
    try {
      const detail = await getRelease(scanId)
      if (releaseRequestRef.current !== token) return
      setLatestRelease(detail)
    } catch {
      // Release fetch is best-effort.
    } finally {
      if (releaseRequestRef.current === token) {
        setLatestReleaseLoading(false)
      }
    }
  }, [])

  useEffect(() => {
    if (!deepLinkScanId) return
    void loadRelease(deepLinkScanId)
    return () => { releaseRequestRef.current++ }
  }, [deepLinkScanId, loadRelease])

  useEffect(() => {
    if (deepLinkScanId || !repoId) return
    let cancelled = false
    listReleases({ repo_id: repoId, limit: 1 })
      .then(async (res) => {
        const summary = res.releases[0]
        if (!summary || cancelled) return
        await loadRelease(summary.scan_id)
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [deepLinkScanId, repoId, loadRelease])

  const handleLatestScan = useCallback((scanId: string) => {
    void getRepo(repoId)
      .then(data => { if (data) setRepo(data) })
      .catch(() => {})
    void loadRelease(scanId)
  }, [repoId, loadRelease])

  const handleShareScanLink = useCallback(() => {
    if (!latestRelease) return
    const url = `${window.location.origin}/repos/${encodeURIComponent(repoId)}?scan_id=${encodeURIComponent(latestRelease.scan_id)}`
    void navigator.clipboard?.writeText(url).catch(() => {})
  }, [repoId, latestRelease])

  const filteredFindings = useMemo(() => {
    if (findingsFilter === "all") return repo.active_findings
    return repo.active_findings.filter((f) => categoryForTool(f.tool) === findingsFilter)
  }, [repo.active_findings, findingsFilter])

  const findingsCountByFilter = useMemo(() => {
    const counts: Record<FindingsSubFilter, number> = {
      all: repo.active_findings.length,
      dependencies: 0,
      code: 0,
      secrets: 0,
      container: 0,
    }
    for (const f of repo.active_findings) {
      const cat = categoryForTool(f.tool)
      if (cat) counts[cat] += 1
    }
    return counts
  }, [repo.active_findings])

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
    <div className="flex flex-col">
      <PageHeader
        icon={<ReposIcon />}
        title={repo.repo}
        description={repo.repo_id}
      />

      <div className="px-6 py-6">
        <RepoDetailHero repo={repo} />
      </div>

      <div className="border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6">
        <div className="flex gap-1">
          {TABS.map(({ id, label }) => (
            <button
              key={id}
              type="button"
              onClick={() => setTab(id)}
              className={`-mb-px border-b-2 px-3 py-2.5 text-sm transition-colors ${
                tab === id
                  ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
                  : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {tab === "overview" && (
        <div className="flex flex-col gap-5 px-6 py-6">
          {(latestRelease || latestReleaseLoading) && (
            <ReleaseVerdictCard
              release={latestRelease}
              loading={latestReleaseLoading}
              onShareLink={handleShareScanLink}
            />
          )}

          <section className="flex flex-col gap-2">
            <h2 className="text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
              Scanner coverage
            </h2>
            <ScannerCoverageStrip
              covered={repo.scanners_with_coverage}
              activeFindings={repo.active_findings}
            />
          </section>

        </div>
      )}

      {tab === "findings" && (
        <div className="flex flex-col gap-4 px-6 py-6">
          <div className="flex flex-wrap items-center gap-2">
            {FINDINGS_SUB_FILTERS.map((f) => {
              const count = findingsCountByFilter[f.id]
              return (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => setFindingsFilter(f.id)}
                  className={`rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors ${
                    findingsFilter === f.id
                      ? "border-[var(--color-accent)]/50 bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                      : "border-[var(--color-border)] bg-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                  }`}
                >
                  {f.label}
                  <span className="ml-2 text-[var(--color-text-tertiary)] tabular-nums">{count}</span>
                </button>
              )
            })}
          </div>
          <div className="overflow-auto rounded-2xl border border-[var(--color-border)]">
            {filteredFindings.length === 0 ? (
              <p className="py-10 text-center text-sm text-[var(--color-text-secondary)]">
                {repo.active_findings.length === 0
                  ? "No open findings for this repo."
                  : "No findings in this category."}
              </p>
            ) : (
              <table className="min-w-full divide-y divide-[var(--color-border)] text-sm">
                <thead className="bg-[var(--color-surface-raised)] text-left text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
                  <tr>
                    <th className="px-5 py-3">Scanner</th>
                    <th className="px-5 py-3">Finding</th>
                    <th className="px-5 py-3">Severity</th>
                    <th className="px-5 py-3">First seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border)]">
                  {filteredFindings.map((f) => (
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
        </div>
      )}

      {tab === "scans" && (
        <div className="px-6 py-6 space-y-6">
          <PreReleaseScanPanel repoId={repoId} onScanComplete={handleLatestScan} />
          <ReleaseVerdictCard
            release={latestRelease}
            loading={latestReleaseLoading}
            onShareLink={handleShareScanLink}
          />
          {latestRelease && (
            <>
              <BlockerDiffList
                blockers={latestRelease.blockers_diff}
                emptyMessage="No blockers in this release."
                baselineRef={latestRelease.baseline_ref}
              />
              <ImprovementsList improvements={latestRelease.improvements} />
            </>
          )}
          <RecentReleaseChecksTable releases={recentReleases} loading={recentReleasesLoading} />
          <ScanHistoryTimeline runs={repo.scan_history} />
        </div>
      )}
    </div>
  )
}
