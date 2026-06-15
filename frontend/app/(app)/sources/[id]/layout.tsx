"use client"

import { use, useEffect, useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { ArrowLeft, Database, RefreshCw } from "lucide-react"
import { PageHeader } from "@/components/layout/PageHeader"
import { TypeChip } from "@/components/ui/TypeChip"
import { getSourceConnection } from "@/lib/client/sources-api"
import { CATEGORY_LABELS } from "@/lib/shared/sources-types"
import type { SourceConnection, SourceCategory } from "@/lib/shared/sources-types"
import { cn } from "@/lib/shared/utils"

// ─── Adapter map ───────────────────────────────────────────────────────────────

const CATEGORY_TO_UI: Record<SourceCategory, "code" | "containers" | "cloud"> = {
  "code-repositories": "code",
  "container-registry": "containers",
  "cloud-infrastructure": "cloud",
}

// ─── Tab definitions ───────────────────────────────────────────────────────────

const TABS = [
  { label: "Overview",       href: "" },
  { label: "Findings",       href: "/findings" },
  { label: "Scans",          href: "/scans" },
  { label: "CI integration", href: "/ci-integration" },
  { label: "Settings",       href: "/settings" },
]

// ─── Layout ────────────────────────────────────────────────────────────────────

export default function SourceDetailLayout({
  children,
  params,
}: {
  children: React.ReactNode
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)
  const pathname = usePathname()
  const [connection, setConnection] = useState<SourceConnection | null>(null)
  const [scanning, setScanning] = useState(false)

  useEffect(() => {
    let cancelled = false
    getSourceConnection(id).then((r) => {
      if (!cancelled && r.ok) setConnection(r.data.connection)
    })
    return () => { cancelled = true }
  }, [id])

  const baseHref = `/sources/${id}`

  function isActive(tabHref: string): boolean {
    const full = `${baseHref}${tabHref}`
    if (tabHref === "") return pathname === baseHref
    return pathname.startsWith(full)
  }

  return (
    <div className="flex flex-col min-h-0">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 px-6 pt-4 pb-0">
        <Link
          href="/sources"
          className="inline-flex items-center gap-1.5 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Sources
        </Link>
      </div>

      {/* Page header */}
      <PageHeader
        icon={<Database className="h-5 w-5" />}
        title={connection?.name ?? "Loading…"}
        description={connection ? CATEGORY_LABELS[connection.category] : ""}
        meta={connection ? <TypeChip type={CATEGORY_TO_UI[connection.category]} /> : undefined}
        controls={
          <button
            disabled={!connection || scanning}
            onClick={() => setScanning(true)}
            className="inline-flex items-center gap-1.5 rounded border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)] disabled:cursor-not-allowed disabled:opacity-40"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", scanning && "animate-spin")} />
            Scan now
          </button>
        }
      />

      {/* Tab nav */}
      <nav className="border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6">
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
