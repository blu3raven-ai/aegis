"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import { use } from "react"
import { ChainGraph, type ChainGraphNode, type ChainGraphEdge } from "@/components/shared/chain/ChainGraph"
import { ChainBadge } from "@/components/shared/chain/ChainBadge"
import { GoNoGoBanner } from "@/components/shared/chain/GoNoGoBanner"
import { ArgusTag } from "@/components/shared/chain/ArgusTag"
import { RiskScoreCell } from "@/components/shared/chain/RiskScoreCell"
import { DrawerSection } from "@/components/shared/FindingDrawer/DrawerSection"
import { getChain, type ChainDetail } from "@/lib/client/chains-api"
import { useLicense } from "@/lib/client/license/client"

// ── Demo graph data (graph-ready shape not yet provided by backend) ───────────

const DEMO_NODES: ChainGraphNode[] = [
  { id: "n1", nodeType: "Entry",  title: "Public HTTP ingress", meta: "GET /v1/orders/*", severity: "low" },
  { id: "n2", nodeType: "SAST",   title: "Untrusted input → logger.info()", meta: "RequestHandler.java:42", severity: "high" },
  { id: "n3", nodeType: "Dep",    title: "log4j@2.14.1 — JNDI RCE", meta: "CVE-2021-44228 · EPSS 0.91", severity: "critical" },
  { id: "n4", nodeType: "Impact", title: "Remote Code Execution", meta: "CVSS 10.0", severity: "critical" },
]

const DEMO_EDGES: ChainGraphEdge[] = [
  { id: "e1", source: "n1", target: "n2", label: "public ingress" },
  { id: "e2", source: "n2", target: "n3", label: "taint flow" },
  { id: "e3", source: "n3", target: "n4", label: "JNDI evaluation" },
]

const SEV_COLOR: Record<string, string> = {
  critical: "var(--color-severity-critical)",
  high: "var(--color-severity-high)",
  medium: "var(--color-severity-medium)",
  low: "var(--color-severity-low)",
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ChainDetailPage({ params }: { params: Promise<{ chainId: string }> }) {
  const { chainId } = use(params)
  const [chain, setChain] = useState<ChainDetail | null>(null)
  const [graphNodes] = useState<ChainGraphNode[]>(DEMO_NODES)
  const [graphEdges] = useState<ChainGraphEdge[]>(DEMO_EDGES)
  const [viewMode, setViewMode] = useState<"graph" | "list">("graph")
  const [drawerOpen, setDrawerOpen] = useState(true)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notFound, setNotFound] = useState(false)
  const { tier } = useLicense()
  const isEnterprise = tier === "enterprise"

  useEffect(() => {
    setLoading(true)
    setError(null)
    setNotFound(false)
    getChain(chainId)
      .then((c) => {
        if (!c) setNotFound(true)
        else setChain(c)
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load chain")
      })
      .finally(() => setLoading(false))
  }, [chainId])

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center bg-[var(--color-bg)]">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--color-accent)] border-t-transparent" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex h-full items-center justify-center bg-[var(--color-bg)]">
        <div className="rounded-xl border border-[var(--color-severity-high)] bg-[var(--color-surface)] px-6 py-5 text-center max-w-sm">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">Failed to load chain</p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">{error}</p>
        </div>
      </div>
    )
  }

  if (notFound || !chain) {
    return (
      <div className="flex h-full items-center justify-center bg-[var(--color-bg)]">
        <div className="text-center">
          <p className="text-sm font-medium text-[var(--color-text-primary)]">Chain not found</p>
          <Link
            href="/chains"
            className="mt-2 inline-block text-xs text-[var(--color-accent)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
          >
            Back to Chains
          </Link>
        </div>
      </div>
    )
  }

  const sevColor = SEV_COLOR[chain.severity] ?? SEV_COLOR.low

  return (
    <div className="flex h-full flex-col overflow-hidden bg-[var(--color-bg)]">
      {/* Top bar / breadcrumb */}
      <div className="flex items-center gap-2 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-5 h-14 text-[13px]">
        <Link
          href="/chains"
          className="text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          Chains
        </Link>
        <svg className="h-3.5 w-3.5 text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}><path d="M9 18l6-6-6-6" /></svg>
        <span className="text-[var(--color-text-primary)] font-medium truncate max-w-[30ch]">
          {chain.chain_type}
        </span>
        <span className="font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-text-tertiary)]">
          {chainId.slice(0, 12)}…
        </span>

        <div className="ml-auto flex items-center gap-2">
          {/* View toggle: graph / list */}
          <div
            className="flex items-center rounded-lg border border-[var(--color-border)] overflow-hidden"
            role="radiogroup"
            aria-label="Chain view mode"
          >
            {(["graph", "list"] as const).map((m) => (
              <button
                key={m}
                type="button"
                role="radio"
                aria-checked={viewMode === m}
                onClick={() => setViewMode(m)}
                className={`px-3 py-1.5 text-xs font-semibold transition-colors border-r last:border-r-0 border-[var(--color-border)] capitalize ${
                  viewMode === m
                    ? "bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                    : "bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                }`}
              >
                {m}
              </button>
            ))}
          </div>

          {/* Toggle drawer */}
          <button
            type="button"
            onClick={() => setDrawerOpen((prev) => !prev)}
            className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
          >
            {drawerOpen ? "Hide details" : "Show details"}
          </button>
        </div>
      </div>

      {/* Page title */}
      <div className="border-b border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-4">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-lg font-semibold tracking-tight text-[var(--color-text-primary)]">
            {chain.chain_type.replace(/-/g, " ")}
          </h1>
          <ChainBadge chainType={chain.chain_type} size="md" />
          <span
            className="inline-flex items-center gap-1.5 rounded-xl px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide border"
            style={{
              color: sevColor,
              background: `color-mix(in srgb, ${sevColor} 13%, transparent)`,
              borderColor: `color-mix(in srgb, ${sevColor} 25%, transparent)`,
            }}
          >
            <span className="inline-block h-[5px] w-[5px] rounded-full bg-current" />
            {chain.severity}
          </span>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-4 text-[13px] text-[var(--color-text-secondary)]">
          <span className="flex items-center gap-1.5">
            <span className="text-[var(--color-text-tertiary)]">Nodes</span>
            <strong className="text-[var(--color-text-primary)] font-medium">{graphNodes.length}</strong>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="text-[var(--color-text-tertiary)]">Edges</span>
            <strong className="text-[var(--color-text-primary)] font-medium">{graphEdges.length}</strong>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="text-[var(--color-text-tertiary)]">Status</span>
            <strong className="capitalize text-[var(--color-text-primary)]">
              {chain.status}
            </strong>
          </span>
        </div>
      </div>

      {/* Canvas + detail drawer */}
      <div className="flex flex-1 overflow-hidden">
        {/* Graph canvas */}
        <div className="flex flex-1 flex-col overflow-hidden p-5 gap-3">
            {viewMode === "graph" ? (
            <ChainGraph
              nodes={graphNodes}
              edges={graphEdges}
              chainId={chainId}
              chainType={chain.chain_type}
            />
          ) : (
            <div className="flex-1 overflow-auto rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-[var(--shadow-card)]">
              <ChainGraph
                nodes={graphNodes}
                edges={graphEdges}
                chainId={chainId}
                chainType={chain.chain_type}
                forceFallback
              />
            </div>
          )}
        </div>

        {/* Detail drawer (right panel) */}
        {drawerOpen && (
          <aside className="w-[420px] shrink-0 border-l border-[var(--color-border)] bg-[var(--color-surface)] overflow-y-auto flex flex-col">
            {/* Go/No-Go verdict */}
            <GoNoGoBanner
              verdict="risk"
              title="No-Go — Block deployment"
              description="This chain includes an actively-exploited CVE with EPSS 0.91 and a reachable code path to the vulnerable dependency."
              isEnterprise={isEnterprise}
            />

            {/* Risk panel */}
            <div className="grid grid-cols-3 divide-x divide-[var(--color-border-divider)] border-b border-[var(--color-border-divider)] mt-4">
              {[
                { label: "Risk Score", value: "94", sub: "/100", argus: true, valueColor: "var(--color-severity-critical)" },
                { label: "EPSS", value: "0.91", sub: "top 2%", argus: false, valueColor: "var(--color-text-primary)" },
                { label: "CVSS", value: "10.0", sub: "critical", argus: false, valueColor: "var(--color-text-primary)" },
              ].map(({ label, value, sub, argus, valueColor }) => (
                <div key={label} className="px-5 py-3">
                  <div className="flex items-center gap-1 text-2xs font-semibold uppercase tracking-wide text-[var(--color-text-tertiary)] mb-1">
                    {label}
                    {argus && <ArgusTag />}
                  </div>
                  <div className="text-[17px] font-semibold" style={{ color: valueColor }}>
                    {value}
                    <span className="ml-1 text-[11px] font-normal text-[var(--color-text-tertiary)]">{sub}</span>
                  </div>
                </div>
              ))}
            </div>

            {/* Sections */}
            <div className="flex flex-col divide-y divide-[var(--color-border-divider)]">
              <section className="px-5 py-4">
                <DrawerSection label="AI Explanation">
                  <p className="text-[13px] text-[var(--color-text-secondary)] leading-relaxed">
                    This chain represents a complete exploit path from an unauthenticated HTTP endpoint through an untrusted taint flow into{" "}
                    <code className="rounded bg-[var(--color-bg-section)] border border-[var(--color-border)] px-1.5 py-px font-[family-name:var(--font-jetbrains-mono)] text-[11px] text-[var(--color-state-dismissed)]">
                      log4j@2.14.1
                    </code>
                    , resulting in remote code execution via JNDI lookup.
                  </p>
                </DrawerSection>
              </section>

              <section className="px-5 py-4">
                <DrawerSection label="Remediation">
                  <ol className="flex flex-col gap-2">
                    {[
                      { n: 1, title: "Upgrade log4j to 2.17.1+", detail: "Removes the JNDI lookup feature entirely" },
                      { n: 2, title: "Add input sanitisation at ingress", detail: "RequestHandler.java:42" },
                      { n: 3, title: "Apply WAF rule for ${jndi: pattern", detail: "Immediate mitigation" },
                    ].map(({ n, title, detail }) => (
                      <li
                        key={n}
                        className="flex items-start gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-3 text-[12px]"
                      >
                        <span className="inline-flex h-[22px] w-[22px] shrink-0 items-center justify-center rounded-[5px] bg-[var(--color-accent-subtle)] text-[11px] font-bold text-[var(--color-accent)]">
                          {n}
                        </span>
                        <div>
                          <p className="font-medium text-[var(--color-text-primary)]">{title}</p>
                          <p className="mt-0.5 text-[11px] text-[var(--color-text-tertiary)]">{detail}</p>
                        </div>
                      </li>
                    ))}
                  </ol>
                </DrawerSection>
              </section>

              <section className="px-5 py-4">
                <DrawerSection label="Affected Services">
                  <ul className="flex flex-col gap-1.5">
                    {[
                      { name: "api-service", role: "entry + vulnerable dep" },
                      { name: "order-processor", role: "downstream consumer" },
                    ].map(({ name, role }) => (
                      <li
                        key={name}
                        className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 text-[12px]"
                      >
                        <span className="h-2 w-2 rounded-full bg-[var(--color-severity-critical)] shrink-0" />
                        <span className="font-[family-name:var(--font-jetbrains-mono)] text-[var(--color-text-primary)]">{name}</span>
                        <span className="ml-auto text-[11px] text-[var(--color-text-tertiary)]">{role}</span>
                      </li>
                    ))}
                  </ul>
                </DrawerSection>
              </section>
            </div>

            {/* Footer actions */}
            <div className="sticky bottom-0 mt-auto flex gap-2 border-t border-[var(--color-border-divider)] bg-[var(--color-surface)] px-5 py-3.5">
              <button
                type="button"
                className="flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 text-[12.5px] font-medium text-[var(--color-text-primary)] hover:border-[var(--color-border-strong)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
              >
                Acknowledge
              </button>
              <button
                type="button"
                className="flex-1 rounded-lg border border-transparent bg-[var(--color-accent)] px-3 py-2 text-[12.5px] font-semibold text-[var(--color-accent-ink,#070d19)] hover:bg-[var(--color-accent-hover)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
              >
                Create ticket
              </button>
            </div>
          </aside>
        )}
      </div>
    </div>
  )
}
