"use client"

import { useCallback, useEffect, useState } from "react"
import { SbomScanSelector } from "@/components/shared/sbom/SbomScanSelector"
import { SbomDiffView } from "@/components/shared/sbom/SbomDiffView"
import { PageHeader } from "@/components/layout/PageHeader"
import { Button } from "@/components/ui/Button"
import { SbomDiffIcon } from "@/lib/shared/ui/page-icons"
import { diffSbomsByRepo, type SbomDiffResponse } from "@/lib/client/sbom-diff-api"
import { listRepos } from "@/lib/client/repos-api"

type DiffState = "idle" | "loading" | "ok" | "error"

export default function SbomDiffPage() {
  const [repoIds, setRepoIds] = useState<string[]>([])
  const [, setReposLoading] = useState(true)
  const [reposError, setReposError] = useState<string | null>(null)

  const [sideARepo, setSideARepo] = useState<string | null>(null)
  const [sideAHash, setSideAHash] = useState<string | null>(null)
  const [sideBRepo, setSideBRepo] = useState<string | null>(null)
  const [sideBHash, setSideBHash] = useState<string | null>(null)

  const [diffState, setDiffState] = useState<DiffState>("idle")
  const [diffResult, setDiffResult] = useState<SbomDiffResponse | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  useEffect(() => {
    listRepos({ limit: 200 })
      .then((result) => {
        setRepoIds(result.map((r) => r.repo_id))
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

  const canCompare =
    sideARepo !== null &&
    sideAHash !== null &&
    sideBRepo !== null &&
    sideBHash !== null &&
    diffState !== "loading"

  const handleCompare = useCallback(async () => {
    if (!sideARepo || !sideAHash || !sideBRepo || !sideBHash) return

    setDiffState("loading")
    setDiffResult(null)
    setErrorMessage(null)

    try {
      const result = await diffSbomsByRepo({
        repo_id: sideARepo,
        from_hash: sideAHash,
        to_hash: sideBHash,
      })
      setDiffResult(result)
      setDiffState("ok")
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "An unexpected error occurred.")
      setDiffState("error")
    }
  }, [sideARepo, sideAHash, sideBRepo, sideBHash])

  return (
    <div className="flex h-full flex-col overflow-y-auto bg-[var(--color-bg)]">
      <PageHeader
        icon={<SbomDiffIcon />}
        title="SBOM diff"
        description="Compare two SBOM snapshots to see package changes"
      />

      <div className="mx-auto w-full max-w-5xl flex-1 px-5 py-6">
        {reposError && (
          <div className="mb-4 flex items-center gap-3 rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3">
            <svg className="h-4 w-4 shrink-0 text-[var(--color-severity-critical)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
            </svg>
            <p className="text-sm text-[var(--color-severity-critical)]">{reposError}</p>
          </div>
        )}

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <SbomScanSelector
            label="Side A — base"
            repoIds={repoIds}
            selectedRepoId={sideARepo}
            selectedHash={sideAHash}
            onRepoChange={setSideARepo}
            onHashChange={setSideAHash}
          />
          <SbomScanSelector
            label="Side B — target"
            repoIds={repoIds}
            selectedRepoId={sideBRepo}
            selectedHash={sideBHash}
            onRepoChange={setSideBRepo}
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

        {diffState === "error" && errorMessage && (
          <div className="mt-6 flex items-start gap-3 rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3">
            <svg className="mt-0.5 h-4 w-4 shrink-0 text-[var(--color-severity-critical)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
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
            >
              <path d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" />
            </svg>
            <p className="text-sm font-medium text-[var(--color-text-secondary)]">
              Select two snapshots and click Compare
            </p>
            <p className="max-w-sm text-xs text-[var(--color-text-tertiary)]">
              Choose a repository and snapshot for each side, then compare to see added, removed, and version-bumped packages.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
