"use client"

import { useState, useEffect, useCallback, useMemo } from "react"
import { MobileSidebarProvider } from "@/components/layout/MobileSidebarContext"
import { LicenseProvider } from "@/lib/client/license/client"
import { AppHeader } from "@/components/layout/AppHeader"
import { MobileSidebar } from "@/components/layout/MobileSidebar"
import { SSEProvider, useSSE } from "@/components/providers/SSEProvider"
import { ScanProgressProvider } from "@/components/providers/ScanProgressProvider"
import { gqlQuery } from "@/lib/client/graphql-client"
import { SCANNER_COUNTS_QUERY } from "@/lib/shared/graphql/queries"
import type { GqlScannerCounts } from "@/lib/shared/graphql/types"
import { AppSidebar } from "./AppSidebar"
import type { AppSidebarProps } from "./AppSidebar"

type SidebarConfig = Omit<AppSidebarProps, "open" | "setSearchOpen">

interface ToolBucket {
  total: number
  critical: number
  high: number
}

const EMPTY_BUCKET: ToolBucket = { total: 0, critical: 0, high: 0 }

function AppShellInner({ children, sidebarProps }: { children: React.ReactNode; sidebarProps: SidebarConfig }) {
  const [searchOpen, setSearchOpen] = useState(false)
  const [toolBuckets, setToolBuckets] = useState<{
    dependencies?: ToolBucket
    container_scanning?: ToolBucket
    code_scanning?: ToolBucket
    secrets?: ToolBucket
  }>({})
  const fetchScannerCounts = useCallback(async () => {
    try {
      const data = await gqlQuery<GqlScannerCounts>(SCANNER_COUNTS_QUERY, {})
      const { dependenciesScanning, codeScanning, containerScanning, secretScanning } = data.scans
      setToolBuckets({
        dependencies: { total: dependenciesScanning.counts.total, critical: dependenciesScanning.counts.critical, high: dependenciesScanning.counts.high },
        container_scanning: { total: containerScanning.counts.total, critical: containerScanning.counts.critical, high: containerScanning.counts.high },
        code_scanning: { total: codeScanning.counts.total, critical: codeScanning.counts.critical, high: codeScanning.counts.high },
        secrets: { total: secretScanning.counts.total, critical: secretScanning.counts.critical, high: secretScanning.counts.high },
      })
    } catch {
      // no findings yet
    }
  }, [])

  useEffect(() => {
    void fetchScannerCounts()
  }, [fetchScannerCounts])

  const navCounts = useMemo(() => {
    const deps = toolBuckets.dependencies ?? EMPTY_BUCKET
    const cont = toolBuckets.container_scanning ?? EMPTY_BUCKET
    const code = toolBuckets.code_scanning ?? EMPTY_BUCKET
    const sec = toolBuckets.secrets ?? EMPTY_BUCKET
    return {
      findings: deps.total + cont.total + code.total + sec.total,
      inbox:
        deps.critical + deps.high +
        cont.critical + cont.high +
        code.critical + code.high +
        sec.critical + sec.high,
    }
  }, [toolBuckets])

  // Refresh sidebar counts when any scan completes via SSE
  useSSE("scan.completed", () => {
    void fetchScannerCounts()
  })

  return (
    <MobileSidebarProvider>
      <div className="flex h-screen overflow-hidden bg-[var(--color-bg)]">
        <AppSidebar {...sidebarProps} navCounts={navCounts} open={searchOpen} setSearchOpen={setSearchOpen} />
        <MobileSidebar {...sidebarProps} navCounts={navCounts} collapsed={false} />
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
      <ScanProgressProvider>
        <AppShellInner sidebarProps={sidebarProps}>{children}</AppShellInner>
      </ScanProgressProvider>
    </SSEProvider>
  )
}
