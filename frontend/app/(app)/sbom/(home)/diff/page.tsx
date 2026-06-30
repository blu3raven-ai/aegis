"use client"

import { useCallback, useEffect, useState } from "react"
import { SbomScanSelector, type RepoOption } from "@/components/shared/sbom/SbomScanSelector"
import { SbomDiffView } from "@/components/shared/sbom/SbomDiffView"
import { Button } from "@/components/ui/Button"
import { diffSbomsByRepo, type SbomDiffResponse } from "@/lib/client/sbom-diff-api"
import { listReposWithCount } from "@/lib/client/sources-api"

type DiffState = "idle" | "loading" | "ok" | "error"

const REPO_LIMIT = 200

export default function SbomDiffPage() {
  const [repos, setRepos] = useState<RepoOption[]>([])
  const [reposTotal, setReposTotal] = useState<number | null>(null)
  const [reposLoading, setReposLoading] = useState(true)
  const [reposError, setReposError] = useState<string | null>(null)

  const [sideARepo, setSideARepo] = useState<string | null>(null)
  const [sideAHash, setSideAHash] = useState<string | null>(null)
  // Side B always compares the same repo as Side A (the diff API is single-repo,
  // two-snapshot), so there is no independent Side B repo — only a snapshot.
  const [sideBHash, setSideBHash] = useState<string | null>(null)

  const [diffState, setDiffState] = useState<DiffState>("idle")
  const [diffResult, setDiffResult] = useState<SbomDiffResponse | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  const loadRepos = useCallback(() => {
    setReposLoading(true)
    setReposError(null)
    listReposWithCount({ limit: REPO_LIMIT })
      .then(({ repos: fetched, totalCount }) => {
        setRepos(
          fetched.map((r) => ({
            id: r.repo_id,
            label: r.display_name || [r.org, r.repo].filter(Boolean).join("/") || r.repo_id,
          })),
        )
        setReposTotal(totalCount)
      })
      .catch((err) => {
        setReposError(
          err instanceof Error ? err.message : "Failed to load repositories",
        )
      })
      .finally(() => {
        setReposLoading(false)
      })
  }, [])

  useEffect(() => {
    loadRepos()
  }, [loadRepos])

  // Both sides default to the same repo's latest snapshot; comparing a snapshot
  // against itself yields a misleading "0 changes", so require distinct hashes.
  const sameSnapshot =
    sideAHash !== null && sideBHash !== null && sideAHash === sideBHash
  const canCompare =
    sideARepo !== null &&
    sideAHash !== null &&
    sideBHash !== null &&
    !sameSnapshot &&
    diffState !== "loading"

  // A rendered diff reflects one specific (repo, base, target) triple. The
  // moment any selector changes, that result no longer matches the controls
  // above it — drop it so the user can't read a stale comparison.
  useEffect(() => {
    setDiffState((s) => (s === "ok" || s === "error" ? "idle" : s))
    setDiffResult(null)
    setErrorMessage(null)
  }, [sideARepo, sideAHash, sideBHash])

  // Concise text announced to screen readers when a comparison completes — the
  // full diff table is too verbose to read aloud, so summarise the deltas.
  const diffStatus =
    diffState === "ok" && diffResult
      ? `Comparison complete: ${diffResult.added_count} added, ${diffResult.removed_count} removed, ${diffResult.version_changed_count} changed.`
      : ""

  const handleCompare = useCallback(async () => {
    if (!sideARepo || !sideAHash || !sideBHash) return

    setDiffState("loading")
    setDiffResult(null)
    setErrorMessage(null)

    try {
      const result = await diffSbomsByRepo({
        repo_id: sideARepo,
        from_run_id: sideAHash,
        to_run_id: sideBHash,
      })
      setDiffResult(result)
      setDiffState("ok")
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "An unexpected error occurred.")
      setDiffState("error")
    }
  }, [sideARepo, sideAHash, sideBHash])

  return (
    <div className="px-6 py-6">
      {reposError && (
        <div role="alert" className="mb-4 flex items-center gap-3 rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3">
          <svg className="h-4 w-4 shrink-0 text-[var(--color-severity-critical)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
          </svg>
          <p className="text-sm text-[var(--color-severity-critical)]">{reposError}</p>
          <Button variant="secondary" size="xs" onClick={loadRepos} className="ml-auto">Retry</Button>
        </div>
      )}

      {reposTotal != null && reposTotal > repos.length && (
        <p className="text-2xs text-[var(--color-text-secondary)]">
          Showing the first {repos.length.toLocaleString()} of {reposTotal.toLocaleString()} repositories.
          Use the repository&apos;s SBOM page to compare one outside this list.
        </p>
      )}

      <div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <SbomScanSelector
            label="Side A — base"
            repos={repos}
            reposLoading={reposLoading}
            selectedRepoId={sideARepo}
            selectedHash={sideAHash}
            onRepoChange={setSideARepo}
            onHashChange={setSideAHash}
          />
          <SbomScanSelector
            label="Side B — target"
            repos={repos}
            lockRepo
            selectedRepoId={sideARepo}
            selectedHash={sideBHash}
            onHashChange={setSideBHash}
          />
        </div>

        <div className="mt-4 flex justify-center">
          <Button
            variant="primary"
            size="md"
            disabled={!canCompare}
            isLoading={diffState === "loading"}
            onClick={() => void handleCompare()}
            leadingIcon={
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />
              </svg>
            }
          >
            {diffState === "loading" ? "Comparing…" : "Compare"}
          </Button>
        </div>

        {sameSnapshot && (
          <p className="mt-2 text-2xs text-[var(--color-text-tertiary)]">
            Pick two different snapshots to compare — both sides are the same snapshot.
          </p>
        )}
      </div>

      {/* Persistently-mounted polite region: announces the comparison summary
          without reading the whole diff table aloud. */}
      <div role="status" aria-live="polite" className="sr-only">
        {diffStatus}
      </div>

      {diffState === "error" && errorMessage && (
        <div role="alert" className="mt-6 flex items-start gap-3 rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3">
          <svg className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-severity-critical)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
          </svg>
          <p className="text-sm text-[var(--color-severity-critical)]">{errorMessage}</p>
        </div>
      )}

      {diffState === "ok" && diffResult && (
        <div className="mt-6 flex flex-col gap-2">
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            Results
          </h2>
          <SbomDiffView diff={diffResult} />
        </div>
      )}

      {diffState === "idle" && (
        <div className="mt-12 flex flex-col items-center justify-center gap-3 text-center">
          <svg
            className="h-12 w-12 text-[var(--color-text-tertiary)]"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.2}
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" />
          </svg>
          <p className="text-sm font-medium text-[var(--color-text-secondary)]">
            Select two snapshots and click Compare
          </p>
          <p className="max-w-sm text-xs text-[var(--color-text-tertiary)]">
            Pick a repository and base snapshot on Side A, then a target snapshot of the same repository on Side B, and compare to see added, removed, and version-bumped packages.
          </p>
        </div>
      )}
    </div>
  )
}
