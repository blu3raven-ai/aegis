"use client"

import Link from "next/link"
import { ChainBadge } from "./ChainBadge"

interface ChainNode {
  id: string | number
  type: string
  title: string
  detail?: string
  severity?: string
}

interface ChainListFallbackProps {
  chainId: string
  chainType: string
  nodes: ChainNode[]
  /** Used when react-flow cannot render (>50 nodes, a11y mode, or server fallback) */
}

const SEV_COLOR: Record<string, string> = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
}

const SCANNER_BG: Record<string, string> = {
  Entry: "var(--color-scanner-entry-bg)",
  SAST: "var(--color-scanner-sast-bg)",
  Dep: "var(--color-scanner-deps-bg)",
  Container: "var(--color-scanner-containers-bg)",
  Secret: "var(--color-scanner-secrets-bg)",
  Impact: "var(--color-scanner-impact-bg)",
}

const SCANNER_TEXT: Record<string, string> = {
  Entry: "var(--color-scanner-entry-fg)",
  SAST: "var(--color-scanner-sast-fg)",
  Dep: "var(--color-scanner-deps-fg)",
  Container: "var(--color-scanner-containers-fg)",
  Secret: "var(--color-scanner-secrets-fg)",
  Impact: "var(--color-scanner-impact-fg)",
}

/**
 * Accessible list-view fallback for the chain graph.
 *
 * Displayed when the graph cannot render (too many nodes, reduced-motion,
 * or server-side). Preserves the full attack-path topology as a linear list.
 */
export function ChainListFallback({ chainId, chainType, nodes }: ChainListFallbackProps) {
  return (
    <div className="flex flex-col gap-0">
      <div className="flex items-center gap-3 px-5 py-3 border-b border-[var(--color-border-divider)]">
        <ChainBadge chainType={chainType} size="md" />
        <span className="text-[11px] text-[var(--color-text-tertiary)]">
          {nodes.length} node{nodes.length !== 1 ? "s" : ""} · list view
        </span>
        <Link
          href={`/chains/${chainId}`}
          className="ml-auto text-xs font-medium text-[var(--color-accent)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          Open graph view →
        </Link>
      </div>

      <ol className="flex flex-col divide-y divide-[var(--color-border-divider)]">
        {nodes.map((node, idx) => {
          const bg = SCANNER_BG[node.type] ?? SCANNER_BG.Dep
          const fg = SCANNER_TEXT[node.type] ?? SCANNER_TEXT.Dep
          const sevColor = node.severity ? (SEV_COLOR[node.severity] ?? SEV_COLOR.low) : undefined

          return (
            <li
              key={node.id}
              className="flex items-start gap-3 px-5 py-3.5 hover:bg-[var(--color-bg-hover)] transition-colors"
            >
              {/* Step number */}
              <span className="mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-[var(--color-border)] bg-[var(--color-bg-section)] text-2xs font-semibold text-[var(--color-text-primary)]">
                {idx + 1}
              </span>

              {/* Scanner type badge */}
              <span
                className="mt-0.5 inline-flex shrink-0 items-center justify-center rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide"
                style={{ background: bg, color: fg }}
              >
                {node.type}
              </span>

              <div className="flex-1 min-w-0">
                <p className="text-[13px] font-medium text-[var(--color-text-primary)] truncate">
                  {node.title}
                </p>
                {node.detail && (
                  <p className="mt-0.5 font-[family-name:var(--font-jetbrains-mono)] text-[10.5px] text-[var(--color-text-tertiary)] truncate">
                    {node.detail}
                  </p>
                )}
              </div>

              {sevColor && (
                <span
                  className="mt-0.5 shrink-0 text-[11px] font-semibold uppercase"
                  style={{ color: sevColor }}
                >
                  {node.severity}
                </span>
              )}
            </li>
          )
        })}
      </ol>
    </div>
  )
}
