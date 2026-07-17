"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import type { SourceCategory } from "@/lib/shared/sources-types"
import { Card } from "@/components/ui/Card"
import { gqlQuery } from "@/lib/client/graphql-client"
import { SCANNER_COUNTS_QUERY } from "@/lib/shared/graphql/queries"
import type { GqlScannerCounts } from "@/lib/shared/graphql/types"


interface ToolInfo {
  label: string
  href: string
  icon: string
  countKey: string
}

const SOURCE_TOOLS: Record<SourceCategory, ToolInfo[]> = {
  "code-repositories": [
    { label: "Dependencies", href: "/findings?scanner=dependencies_scanning", icon: "M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z", countKey: "dependencies" },
    { label: "Code", href: "/findings?scanner=code_scanning", icon: "M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5", countKey: "code_scanning" },
    { label: "Secrets", href: "/findings?scanner=secret_scanning", icon: "M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z", countKey: "secrets" },
    { label: "IaC", href: "/findings?scanner=iac_scanning", icon: "M2.25 7.125C2.25 6.504 2.754 6 3.375 6h6c.621 0 1.125.504 1.125 1.125v3.75c0 .621-.504 1.125-1.125 1.125h-6a1.125 1.125 0 0 1-1.125-1.125v-3.75ZM14.25 8.625c0-.621.504-1.125 1.125-1.125h5.25c.621 0 1.125.504 1.125 1.125v8.25c0 .621-.504 1.125-1.125 1.125h-5.25a1.125 1.125 0 0 1-1.125-1.125v-8.25ZM3.75 16.125c0-.621.504-1.125 1.125-1.125h5.25c.621 0 1.125.504 1.125 1.125v2.25c0 .621-.504 1.125-1.125 1.125h-5.25a1.125 1.125 0 0 1-1.125-1.125v-2.25Z", countKey: "iac" },
  ],
  "container-registry": [
    { label: "Containers", href: "/findings?scanner=container_scanning", icon: "M21 7.5l-9-5.25L3 7.5m18 0l-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9", countKey: "container_scanning" },
  ],
  "cloud-infrastructure": [],
  "ci-systems": [],
}


interface PoweredToolsSectionProps {
  category: SourceCategory
  hasConnections: boolean
}

export function PoweredToolsSection({ category, hasConnections }: PoweredToolsSectionProps) {
  const tools = SOURCE_TOOLS[category]
  const [counts, setCounts] = useState<Record<string, number>>({})

  useEffect(() => {
    if (!hasConnections || tools.length === 0) return
    async function loadCounts() {
      try {
        const data = await gqlQuery<GqlScannerCounts>(SCANNER_COUNTS_QUERY, {})
        setCounts({
          dependencies: data.scans.dependenciesScanning.counts.total,
          code_scanning: data.scans.codeScanning.counts.total,
          secrets: data.scans.secretScanning.counts.total,
          container_scanning: data.scans.containerScanning.counts.total,
          iac: data.scans.iacScanning.counts.total,
        })
      } catch {
        // optional — fail silently
      }
    }
    void loadCounts()
  }, [hasConnections, tools])

  if (tools.length === 0) return null

  return (
    <Card className="rounded-md shadow-[var(--shadow-card)]">
      <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
        Tools powered by this source
      </p>

      <div className="mt-4 divide-y divide-[var(--color-border)]">
        {tools.map((tool) => {
          const count = counts[tool.countKey]
          const hasFindings = typeof count === "number" && count > 0

          if (!hasConnections) {
            return (
              <div key={tool.label} className="flex items-center gap-3 py-3 opacity-50">
                <svg className="h-5 w-5 shrink-0 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
                  <path d={tool.icon} />
                </svg>
                <span className="text-sm font-semibold text-[var(--color-text-primary)]">{tool.label}</span>
                <span className="ml-auto text-xs text-[var(--color-text-tertiary)]">Awaiting connection</span>
              </div>
            )
          }

          return (
            <Link
              key={tool.label}
              href={tool.href}
              className="flex items-center gap-3 py-3 transition-colors hover:bg-[var(--color-bg-hover)] -mx-3 px-3 rounded-lg focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
            >
              <svg className="h-5 w-5 shrink-0 text-[var(--color-text-secondary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
                <path d={tool.icon} />
              </svg>
              <span className="text-sm font-semibold text-[var(--color-text-primary)]">{tool.label}</span>
              <span className="ml-auto flex items-center gap-3">
                {hasFindings ? (
                  <span className="text-xs font-medium tabular-nums text-[var(--color-text-primary)]">{count.toLocaleString()} open findings</span>
                ) : typeof count === "number" ? (
                  <span className="text-xs text-[var(--color-status-ok-text)]">All clear</span>
                ) : (
                  <span className="text-xs text-[var(--color-text-secondary)]">No scans yet</span>
                )}
                <svg className="h-4 w-4 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                  <path d="M9 18l6-6-6-6" />
                </svg>
              </span>
            </Link>
          )
        })}
      </div>
    </Card>
  )
}
