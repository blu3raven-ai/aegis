"use client"

import { useState, useEffect, useCallback } from "react"
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

type SidebarConfig = Omit<AppSidebarProps, "open" | "setSearchOpen">

function AppShellInner({ children, sidebarProps }: { children: React.ReactNode; sidebarProps: SidebarConfig }) {
  const [searchOpen, setSearchOpen] = useState(false)
  const [counts, setCounts] = useState<{ dependencies?: number; containerScanning?: number; codeScanning?: number; secrets?: number }>({})

  const fetchDependenciesCounts = useCallback(async () => {
    try {
      const data = await gqlQuery<{ dependenciesCounts: GqlSeverityCounts }>(DEPENDENCIES_COUNTS_QUERY, {})
      setCounts((prev) => ({ ...prev, dependencies: data.dependenciesCounts.total }))
    } catch {
      // no findings yet
    }
  }, [])

  const fetchContainerScanningCounts = useCallback(async () => {
    try {
      const data = await gqlQuery<{ containerCounts: GqlSeverityCounts }>(CONTAINER_COUNTS_QUERY, {})
      setCounts((prev) => ({ ...prev, containerScanning: data.containerCounts.total }))
    } catch {
      // no findings yet
    }
  }, [])

  const fetchCodeScanningCounts = useCallback(async () => {
    try {
      const data = await gqlQuery<{ codeScanningCounts: GqlSeverityCounts }>(CODE_SCANNING_COUNTS_QUERY, {})
      setCounts((prev) => ({ ...prev, codeScanning: data.codeScanningCounts.total }))
    } catch {
      // no findings yet
    }
  }, [])

  const fetchSecretsCounts = useCallback(async () => {
    try {
      const data = await gqlQuery<{ secretCounts: GqlSeverityCounts }>(SECRET_COUNTS_QUERY, {})
      setCounts((prev) => ({ ...prev, secrets: data.secretCounts.total }))
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

  // Refresh sidebar counts when any scan completes via SSE
  useSSE("scan.completed", (data: ScanCompletedEvent) => {
    if (data.tool === "dependencies") void fetchDependenciesCounts()
    if (data.tool === "container_scanning") void fetchContainerScanningCounts()
    if (data.tool === "code_scanning") void fetchCodeScanningCounts()
    if (data.tool === "secrets") void fetchSecretsCounts()
  })

  return (
    <MobileSidebarProvider>
      <div className="flex h-screen overflow-hidden bg-[var(--color-bg)]">
        <AppSidebar {...sidebarProps} counts={counts} open={searchOpen} setSearchOpen={setSearchOpen} />
        <MobileSidebar {...sidebarProps} counts={counts} collapsed={false} />
        <div className="flex-1 min-w-0 flex flex-col overflow-hidden">
          <AppHeader open={searchOpen} setSearchOpen={setSearchOpen} />
          <main className="flex-1 min-w-0 overflow-y-auto">
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
