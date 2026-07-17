"use client"

import { useMemo, useState } from "react"
import Link from "next/link"

import { type ConnectorType } from "@/lib/client/integrations-catalog-api"
import { type NotificationDestination } from "@/lib/client/destinations-api"

import {
  CATEGORY_DISPLAY,
  CATEGORY_ORDER,
  COMING_SOON_CONNECTORS,
  CatalogConnectorModal,
  ConnectorCard,
} from "./_connectors"

interface IntegrationsBrowseTabProps {
  catalog: ConnectorType[]
  catalogState: "loading" | "ok" | "error"
  destinations: NotificationDestination[]
  isEnterprise: boolean
  onReload: () => void
  onDestinationCreated: (dest: NotificationDestination) => void
}

function BrowseSkeleton() {
  const groups = [4, 3, 3, 2]
  return (
    <div className="space-y-8">
      {groups.map((count, gi) => (
        <div key={gi}>
          <div className="mb-3 h-3 w-24 animate-pulse rounded bg-[var(--color-surface-raised)]" />
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: count }).map((_, ci) => (
              <div
                key={ci}
                className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-5"
              >
                <div className="flex items-start gap-3">
                  <div className="h-9 w-9 shrink-0 animate-pulse rounded-xl bg-[var(--color-surface-raised)]" />
                  <div className="flex-1 space-y-2">
                    <div className="h-4 w-1/2 animate-pulse rounded bg-[var(--color-surface-raised)]" />
                    <div className="h-3 w-full animate-pulse rounded bg-[var(--color-surface-raised)]" />
                    <div className="h-3 w-4/5 animate-pulse rounded bg-[var(--color-surface-raised)]" />
                  </div>
                </div>
                <div className="mt-4 h-8 w-full animate-pulse rounded-lg bg-[var(--color-surface-raised)]" />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

export function IntegrationsBrowseTab({
  catalog,
  catalogState,
  destinations,
  isEnterprise,
  onReload,
  onDestinationCreated,
}: IntegrationsBrowseTabProps) {
  const [configuringConnector, setConfiguringConnector] = useState<ConnectorType | null>(null)
  // "all" sentinel — keeps the active-chip logic explicit instead of nullable comparisons
  const [activeCategory, setActiveCategory] = useState<string>("all")
  const [searchQuery, setSearchQuery] = useState<string>("")

  // Build the combined connector list (live + soon placeholders, with id collisions removed).
  const allConnectors = useMemo(() => {
    const liveIds = new Set(catalog.map((c) => c.id))
    return [...catalog, ...COMING_SOON_CONNECTORS.filter((c) => !liveIds.has(c.id))]
  }, [catalog])

  // Derive categories from the actual data so new backend categories appear automatically.
  const categories = useMemo(() => {
    const counts = new Map<string, number>()
    for (const c of allConnectors) {
      counts.set(c.category, (counts.get(c.category) ?? 0) + 1)
    }
    const ordered = CATEGORY_ORDER.filter((cat) => counts.has(cat))
    const extras = Array.from(counts.keys()).filter((cat) => !CATEGORY_ORDER.includes(cat))
    return [...ordered, ...extras].map((id) => ({
      id,
      label: CATEGORY_DISPLAY[id] ?? id.charAt(0).toUpperCase() + id.slice(1),
      count: counts.get(id) ?? 0,
    }))
  }, [allConnectors])

  const visibleCategories =
    activeCategory === "all"
      ? categories.map((c) => c.id)
      : categories.filter((c) => c.id === activeCategory).map((c) => c.id)

  // Search filters connectors by name/id. Empty query keeps everything.
  const searchMatches = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return null
    return new Set(
      allConnectors
        .filter((c) => c.name.toLowerCase().includes(q) || c.id.toLowerCase().includes(q))
        .map((c) => c.id),
    )
  }, [allConnectors, searchQuery])

  return (
    <div className="px-6 py-8 space-y-8">
      {/* Non-enterprise users see an upgrade prompt */}
      {!isEnterprise && (
        <div className="flex items-center justify-between rounded-2xl border border-[var(--color-state-dismissed-border)] bg-[var(--color-state-dismissed-subtle)] px-6 py-4">
          <div className="flex items-center gap-3">
            <span className="rounded-full bg-[var(--color-state-dismissed-subtle)] px-2.5 py-0.5 text-xs font-semibold text-[var(--color-state-dismissed)]">
              Enterprise
            </span>
            <p className="text-sm text-[var(--color-text-primary)]">
              Most integrations require an Enterprise license. Configure free connectors below.
            </p>
          </div>
          <Link
            href="/settings/license"
            className="shrink-0 rounded-lg border border-[var(--color-state-dismissed-border)] px-4 py-2 text-sm font-semibold text-[var(--color-state-dismissed)] transition-colors hover:bg-[var(--color-state-dismissed-subtle)] focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
          >
            Upgrade
          </Link>
        </div>
      )}

      {catalogState === "loading" && <BrowseSkeleton />}
      {catalogState === "error" && (
        <p className="text-sm text-[var(--color-severity-high)]">
          Failed to load catalog.{" "}
          <button
            type="button"
            onClick={onReload}
            className="underline"
          >
            Retry
          </button>
        </p>
      )}

      {catalogState === "ok" && (
        <>
          {/* Category filter chips + search — mock filter-bar layout. Solid-fill on active per
              design system (segmented toggle, not nav). All vs categories separated by a divider
              per mock. */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setActiveCategory("all")}
              className={`rounded-full px-3 py-1.5 text-xs font-semibold transition-colors ${
                activeCategory === "all"
                  ? "bg-[var(--color-accent)] text-[var(--color-accent-on)]"
                  : "border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:border-[var(--color-accent)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              All
              <span className="ml-1.5 tabular-nums opacity-70">{allConnectors.length}</span>
            </button>
            <span aria-hidden="true" className="h-4 w-px bg-[var(--color-border)]" />
            {categories.map((cat) => {
              const active = activeCategory === cat.id
              return (
                <button
                  key={cat.id}
                  type="button"
                  onClick={() => setActiveCategory(cat.id)}
                  className={`rounded-full px-3 py-1.5 text-xs font-semibold transition-colors ${
                    active
                      ? "bg-[var(--color-accent)] text-[var(--color-accent-on)]"
                      : "border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:border-[var(--color-accent)] hover:text-[var(--color-text-primary)]"
                  }`}
                >
                  {cat.label}
                  <span className="ml-1.5 tabular-nums opacity-70">{cat.count}</span>
                </button>
              )
            })}
            <label className="relative ml-auto flex items-center">
              <svg
                aria-hidden="true"
                className="pointer-events-none absolute left-3 h-3.5 w-3.5 text-[var(--color-text-tertiary)]"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <circle cx="11" cy="11" r="7" />
                <path d="m21 21-4.3-4.3" />
              </svg>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search integrations…"
                aria-label="Search integrations"
                className="w-56 rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] pl-8 pr-3 py-1.5 text-xs text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
              />
            </label>
          </div>

          {(() => {
            const sections = visibleCategories
              .map((cat) => ({
                cat,
                items: allConnectors
                  .filter((c) => c.category === cat)
                  .filter((c) => searchMatches === null || searchMatches.has(c.id)),
              }))
              .filter((s) => s.items.length > 0)

            if (sections.length === 0) {
              return (
                <p className="text-sm text-[var(--color-text-secondary)]">
                  No integrations match{searchQuery.trim() ? ` "${searchQuery.trim()}"` : ""}.
                </p>
              )
            }

            return sections.map(({ cat, items }) => (
              <div key={cat}>
                <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
                  {CATEGORY_DISPLAY[cat] ?? cat}
                </p>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {items.map((connector) => (
                    <ConnectorCard
                      key={connector.id}
                      connector={connector}
                      configured={destinations.some((d) => d.destination_type === connector.id)}
                      canConfigure={!connector.enterprise_only || isEnterprise}
                      onConfigure={() => setConfiguringConnector(connector)}
                    />
                  ))}
                </div>
              </div>
            ))
          })()}
        </>
      )}

      {configuringConnector && (
        <CatalogConnectorModal
          connector={configuringConnector}
          onClose={() => setConfiguringConnector(null)}
          onSaved={(dest) => {
            onDestinationCreated(dest)
            setConfiguringConnector(null)
          }}
        />
      )}
    </div>
  )
}
