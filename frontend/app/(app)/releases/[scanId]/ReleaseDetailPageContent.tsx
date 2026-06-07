"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { useParams } from "next/navigation"
import Link from "next/link"
import { PageHeader } from "@/components/layout/PageHeader"
import { ReposIcon } from "@/lib/shared/ui/page-icons"
import { BlockerDiffList } from "@/components/shared/releases/BlockerDiffList"
import { ImprovementsList } from "@/components/shared/releases/ImprovementsList"
import { ReleaseVerdictCard } from "@/components/shared/releases/ReleaseVerdictCard"
import { getRelease, type ReleaseDetail } from "@/lib/client/releases-api"
import { shortenSha } from "@/components/shared/releases/_helpers"

export function ReleaseDetailPageContent() {
  const params = useParams<{ scanId: string }>()
  const scanId = decodeURIComponent(params.scanId ?? "")

  const [release, setRelease] = useState<ReleaseDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)
  const requestRef = useRef(0)

  useEffect(() => {
    if (!scanId) return
    const token = ++requestRef.current
    setLoading(true)
    setNotFound(false)
    getRelease(scanId)
      .then((data) => {
        if (requestRef.current !== token) return
        if (data) setRelease(data)
        else setNotFound(true)
      })
      .catch(() => {
        // Detail fetch is best-effort — surface as not-found rather than crashing.
        if (requestRef.current !== token) return
        setNotFound(true)
      })
      .finally(() => {
        if (requestRef.current === token) setLoading(false)
      })
  }, [scanId])

  const handleShareScanLink = useCallback(() => {
    if (typeof window === "undefined" || !release) return
    const url = `${window.location.origin}/releases/${encodeURIComponent(release.scan_id)}`
    void navigator.clipboard?.writeText(url).catch(() => {})
  }, [release])

  if (notFound) {
    return (
      <>
        <PageHeader
          icon={<ReposIcon />}
          title="Release scan not found"
          description={scanId}
        />
        <div className="mx-auto flex w-full max-w-7xl flex-col items-center gap-3 px-6 py-16 text-center">
          <p className="text-sm text-[var(--color-text-secondary)]">
            We couldn&apos;t find a release scan with this ID.
          </p>
          <Link
            href="/releases"
            className="text-sm font-semibold text-[var(--color-accent)] hover:underline"
          >
            Back to Releases →
          </Link>
        </div>
      </>
    )
  }

  const refLabel = release?.ref ?? shortenSha(release?.commit_sha)
  const headerTitle = release ? `${release.repo} · ${refLabel}` : "Release scan"
  const headerSub = release ? release.repo_id : scanId

  return (
    <>
      <PageHeader
        icon={<ReposIcon />}
        title={headerTitle}
        description={headerSub}
      />
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-6 py-6">
        <ReleaseVerdictCard
          release={release}
          loading={loading}
          onShareLink={handleShareScanLink}
        />
        {release && (
          <>
            <BlockerDiffList
              blockers={release.blockers_diff}
              emptyMessage="No blockers in this release."
              baselineRef={release.baseline_ref}
            />
            <ImprovementsList improvements={release.improvements} />
          </>
        )}
      </div>
    </>
  )
}
