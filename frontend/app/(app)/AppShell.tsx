"use client"

import { useState, useEffect, useCallback, useMemo } from "react"
import { MobileSidebarProvider } from "@/components/layout/MobileSidebarContext"
import { LicenseProvider } from "@/lib/client/license/client"
import { AppHeader } from "@/components/layout/AppHeader"
import { MobileSidebar } from "@/components/layout/MobileSidebar"
import { SSEProvider, useSSE } from "@/components/providers/SSEProvider"
import { gqlQuery } from "@/lib/client/graphql-client"
import { DEPENDENCIES_COUNTS_QUERY, CONTAINER_COUNTS_QUERY, CODE_SCANNING_COUNTS_QUERY, SECRET_COUNTS_QUERY } from "@/lib/shared/graphql/queries"
import type { GqlSeverityCounts } from "@/lib/shared/graphql/types"
import { AppSidebar } from "./AppSidebar"
import type { AppSidebarProps } from "./AppSidebar"
import type { ScanCompletedEvent } from "@/lib/shared/sse-types"
import { getOnboardingState } from "@/lib/client/onboarding-api"
import { listRepos } from "@/lib/client/repos-api"
import { listImages } from "@/lib/client/images-api"

type SidebarConfig = Omit<AppSidebarProps, "open" | "setSearchOpen">

interface ToolBucket {
  total: number
  critical: number
  high: number
}

const EMPTY_BUCKET: ToolBucket = { total: 0, critical: 0, high: 0 }

function AppShellInner({ children, sidebarProps }: { children: React.ReactNode; sidebarProps: SidebarConfig }) {
  const [searchOpen, setSearchOpen] = useState(false)
  const [counts, setCounts] = useState<{ dependencies?: number; containerScanning?: number; codeScanning?: number; secrets?: number }>({})
  const [toolBuckets, setToolBuckets] = useState<{
    dependencies?: ToolBucket
    containerScanning?: ToolBucket
    codeScanning?: ToolBucket
    secrets?: ToolBucket
  }>({})
  const [reposCount, setReposCount] = useState<number | undefined>(undefined)
  const [imagesCount, setImagesCount] = useState<number | undefined>(undefined)
  const [onboardingComplete, setOnboardingComplete] = useState(true)

  const fetchDependenciesCounts = useCallback(async () => {
    try {
      const data = await gqlQuery<{ dependenciesCounts: GqlSeverityCounts }>(DEPENDENCIES_COUNTS_QUERY, {})
      const c = data.dependenciesCounts
      setCounts((prev) => ({ ...prev, dependencies: c.total }))
      setToolBuckets((prev) => ({ ...prev, dependencies: { total: c.total, critical: c.critical, high: c.high } }))
    } catch {
      // no findings yet
    }
  }, [])

  const fetchContainerScanningCounts = useCallback(async () => {
    try {
      const data = await gqlQuery<{ containerCounts: GqlSeverityCounts }>(CONTAINER_COUNTS_QUERY, {})
      const c = data.containerCounts
      setCounts((prev) => ({ ...prev, containerScanning: c.total }))
      setToolBuckets((prev) => ({ ...prev, containerScanning: { total: c.total, critical: c.critical, high: c.high } }))
    } catch {
      // no findings yet
    }
  }, [])

  const fetchCodeScanningCounts = useCallback(async () => {
    try {
      const data = await gqlQuery<{ codeScanningCounts: GqlSeverityCounts }>(CODE_SCANNING_COUNTS_QUERY, {})
      const c = data.codeScanningCounts
      setCounts((prev) => ({ ...prev, codeScanning: c.total }))
      setToolBuckets((prev) => ({ ...prev, codeScanning: { total: c.total, critical: c.critical, high: c.high } }))
    } catch {
      // no findings yet
    }
  }, [])

  const fetchSecretsCounts = useCallback(async () => {
    try {
      const data = await gqlQuery<{ secretCounts: GqlSeverityCounts }>(SECRET_COUNTS_QUERY, {})
      const c = data.secretCounts
      setCounts((prev) => ({ ...prev, secrets: c.total }))
      setToolBuckets((prev) => ({ ...prev, secrets: { total: c.total, critical: c.critical, high: c.high } }))
    } catch {
      // no findings yet
    }
  }, [])

  useEffect(() => {
    void fetchDependenciesCounts()
    void fetchContainerScanningCounts()
    void fetchCodeScanningCounts()
    void fetchSecretsCounts()
  }, [fetchDependenciesCounts, fetchContainerScanningCounts, fetchCodeScanningCounts, fetchSecretsCounts])

  // Lightweight one-shot fetches for nav-item badge counts on Repositories and Images.
  // Both endpoints already serve summarized data; we only need .length and total_count.
  useEffect(() => {
    let cancelled = false
    listRepos({ limit: 200 })
      .then((rows) => { if (!cancelled) setReposCount(rows.length) })
      .catch(() => { if (!cancelled) setReposCount(undefined) })
    listImages({ limit: 1 })
      .then((res) => { if (!cancelled) setImagesCount(res.total_count) })
      .catch(() => { if (!cancelled) setImagesCount(undefined) })
    return () => { cancelled = true }
  }, [])

  const navCounts = useMemo(() => {
    const deps = toolBuckets.dependencies ?? EMPTY_BUCKET
    const cont = toolBuckets.containerScanning ?? EMPTY_BUCKET
    const code = toolBuckets.codeScanning ?? EMPTY_BUCKET
    const sec = toolBuckets.secrets ?? EMPTY_BUCKET
    const totalAcrossTools = deps.total + cont.total + code.total + sec.total
    const criticalAndHigh =
      deps.critical + deps.high +
      cont.critical + cont.high +
      code.critical + code.high +
      sec.critical + sec.high
    const haveAnyToolData =
      toolBuckets.dependencies !== undefined ||
      toolBuckets.containerScanning !== undefined ||
      toolBuckets.codeScanning !== undefined ||
      toolBuckets.secrets !== undefined
    return {
      findings: haveAnyToolData ? totalAcrossTools : undefined,
      inbox: haveAnyToolData ? criticalAndHigh : undefined,
      repos: reposCount,
      images: imagesCount,
    }
  }, [toolBuckets, reposCount, imagesCount])

  // Refresh sidebar counts when any scan completes via SSE
  useSSE("scan.completed", (data: ScanCompletedEvent) => {
    if (data.tool === "dependencies") void fetchDependenciesCounts()
    if (data.tool === "container_scanning") void fetchContainerScanningCounts()
    if (data.tool === "code_scanning") void fetchCodeScanningCounts()
    if (data.tool === "secrets") void fetchSecretsCounts()
  })

  useEffect(() => {
    const orgId = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"
    getOnboardingState(orgId)
      .then((s) => setOnboardingComplete(s.dismissed))
      .catch(() => {
        // On error assume complete so we don't nag users unnecessarily
        setOnboardingComplete(true)
      })
  }, [])

  return (
    <MobileSidebarProvider>
      <div className="flex h-screen overflow-hidden bg-[var(--color-bg)]">
        <AppSidebar {...sidebarProps} counts={counts} navCounts={navCounts} open={searchOpen} setSearchOpen={setSearchOpen} onboardingComplete={onboardingComplete} />
        <MobileSidebar {...sidebarProps} counts={counts} navCounts={navCounts} collapsed={false} onboardingComplete={onboardingComplete} />
        <div className="flex-1 min-w-0 flex flex-col overflow-hidden">
          <AppHeader open={searchOpen} setSearchOpen={setSearchOpen} />
          <main data-app-scroll className="flex-1 min-w-0 overflow-y-auto">
            <LicenseProvider>
              {children}
            </LicenseProvider>
          </main>
        </div>
      </div>
    </MobileSidebarProvider>
  )
}

export function AppShell({ children, sidebarProps }: { children: React.ReactNode; sidebarProps: SidebarConfig }) {
  return (
    <SSEProvider>
      <AppShellInner sidebarProps={sidebarProps}>{children}</AppShellInner>
    </SSEProvider>
  )
}
