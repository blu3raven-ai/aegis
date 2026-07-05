"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { Database, RefreshCw, Unplug, X } from "lucide-react"
import { PageHeader } from "@/components/layout/PageHeader"
import { Button } from "@/components/ui/Button"
import { EmptyState } from "@/components/ui/EmptyState"
import { TypeChip } from "@/components/ui/TypeChip"
import { getActiveSourceScanRuns, getSourceConnection, scanSourceConnection } from "@/lib/client/source-connections-api"
import { useScanProgress } from "@/components/providers/ScanProgressProvider"
import { useHasPermission } from "@/lib/client/use-permission"
import { useMountedPathname } from "@/lib/client/use-mounted-pathname"
import { useSourceId } from "@/lib/client/use-source-id"
import { IconChipFrame } from "@/lib/shared/ui/page-icons"
import { SourceTypeLogo } from "@/app/(app)/settings/sources/_components/SourceTypeLogo"
import { CATEGORY_LABELS, sourceDisplayName } from "@/lib/shared/sources-types"
import type { SourceConnection, SourceCategory } from "@/lib/shared/sources-types"
import { cn } from "@/lib/shared/utils"


const CATEGORY_TO_UI: Record<SourceCategory, "code" | "containers" | "cloud" | "ci"> = {
  "code-repositories": "code",
  "container-registry": "containers",
  "cloud-infrastructure": "cloud",
  "ci-systems": "ci",
}


const TABS = [
  { label: "Overview",  href: "" },
  { label: "Findings",  href: "/findings" },
  { label: "Scans",     href: "/scans" },
  { label: "Settings",  href: "/settings" },
]


export default function SourceDetailLayout({
  children,
}: {
  children: React.ReactNode
  params: Promise<{ id: string }>
}) {
  const id = useSourceId()
  // Null until mounted so the static-export prerender and first client render
  // agree on the active tab (see useMountedPathname).
  const pathname = useMountedPathname()
  const { isScanning, isCancelling, register, cancel } = useScanProgress()
  // Both starting and cancelling a scan require manage_sources (the permission
  // the /scan and /scan/cancel endpoints enforce); hide the controls otherwise.
  const { allowed: canManageSources } = useHasPermission("manage_sources")
  const [connection, setConnection] = useState<SourceConnection | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [scanning, setScanning] = useState(false)
  const scanActive = isScanning(id)

  useEffect(() => {
    if (!id) return
    let cancelled = false
    Promise.all([
      getSourceConnection(id),
      getActiveSourceScanRuns(id),
    ]).then(([connResult, activeResult]) => {
      if (cancelled) return
      if (connResult.ok) setConnection(connResult.data.connection)
      if (connResult.ok && activeResult.ok && activeResult.data.runIds.length > 0) {
        const conn = connResult.data.connection
        register({
          connectionId: id,
          org: conn.auth.orgOrOwner ?? conn.name,
          runIds: activeResult.data.runIds,
        })
      }
      setLoaded(true)
    })
    return () => { cancelled = true }
  }, [id, register])

  async function handleScanNow() {
    if (!connection || scanning || scanActive) return
    setScanning(true)
    const result = await scanSourceConnection(id)
    setScanning(false)
    if (result.ok && result.data.queued.length > 0) {
      register({
        connectionId: id,
        org: connection.auth.orgOrOwner ?? connection.name,
        runIds: result.data.queued,
      })
    }
  }

  const baseHref = `/sources/${id}`

  function isActive(tabHref: string): boolean {
    if (!pathname) return false
    const full = `${baseHref}${tabHref}`
    if (tabHref === "") return pathname === baseHref
    return pathname.startsWith(full)
  }

  // The fetch resolved but no connection came back — the id in the URL doesn't
  // match any source. Show a dedicated not-found state instead of an empty
  // shell with placeholder dashes across every tab.
  const notFound = loaded && !connection

  if (notFound) {
    return (
      <div className="flex flex-col min-h-0">
        <PageHeader
          icon={
            <IconChipFrame>
              <Database className="h-5 w-5 text-[var(--color-accent)]" />
            </IconChipFrame>
          }
          title="Source not found"
          description="This source connection doesn't exist or was removed"
        />
        <div className="flex-1 overflow-auto px-6 py-10">
          <EmptyState
            icon={Unplug}
            title="We couldn't find this source"
            description="The source connection you're looking for doesn't exist, or it may have been deleted. Check the link or head back to your connected sources."
            cta={
              <Link href="/sources">
                <Button variant="primary">Back to Sources</Button>
              </Link>
            }
          />
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col min-h-0">
      <PageHeader
        icon={
          <IconChipFrame>
            {connection ? (
              <SourceTypeLogo
                type={connection.sourceType}
                size={16}
                className="h-5 w-5 text-[var(--color-accent)]"
              />
            ) : (
              <Database className="h-5 w-5 text-[var(--color-accent)]" />
            )}
          </IconChipFrame>
        }
        title={connection ? sourceDisplayName(connection) : "Loading…"}
        description={connection ? CATEGORY_LABELS[connection.category] : ""}
        meta={connection ? <TypeChip type={CATEGORY_TO_UI[connection.category]} /> : undefined}
        controls={
          scanActive ? (
            <div className="flex items-center gap-2">
              <Button
                variant="secondary"
                disabled
                leadingIcon={<RefreshCw className="h-4 w-4 animate-spin" />}
              >
                Scanning…
              </Button>
              {canManageSources && (
                <Button
                  variant="destructive"
                  onClick={() => void cancel(id)}
                  disabled={isCancelling(id)}
                  leadingIcon={<X className="h-3.5 w-3.5" strokeWidth={2.5} />}
                >
                  {isCancelling(id) ? "Cancelling…" : "Cancel"}
                </Button>
              )}
            </div>
          ) : canManageSources ? (
            <Button
              variant="secondary"
              disabled={!connection || scanning}
              onClick={handleScanNow}
              leadingIcon={<RefreshCw className={cn("h-4 w-4", scanning && "animate-spin")} />}
            >
              Scan Now
            </Button>
          ) : null
        }
      />

      {/* Tab nav */}
      <nav className="sticky top-[var(--page-header-offset)] z-10 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6">
        <div className="flex items-end gap-0">
          {TABS.map((tab) => {
            const active = isActive(tab.href)
            return (
              <Link
                key={tab.href}
                href={`${baseHref}${tab.href}`}
                className={cn(
                  "-mb-px border-b-2 px-3 py-2.5 text-sm transition-colors",
                  active
                    ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
                    : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]",
                )}
              >
                {tab.label}
              </Link>
            )
          })}
        </div>
      </nav>

      {/* Tab content */}
      <div className="flex-1 overflow-auto">
        {children}
      </div>
    </div>
  )
}
