"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import Link from "next/link"

import { getCatalog, type ConnectorType } from "@/lib/client/integrations-catalog-api"
import { listDestinations, type NotificationDestination } from "@/lib/client/destinations-api"
import { useLicense } from "@/lib/client/license/client"
import { Button } from "@/components/ui/Button"
import { FilterChip } from "@/components/ui/FilterChip"
import { Input } from "@/components/ui/Input"
import { Sheet } from "@/components/ui/Sheet"

import {
  CATEGORY_DISPLAY,
  CATEGORY_ORDER,
  COMING_SOON_CONNECTORS,
  CatalogConnectorModal,
  ConnectorCard,
} from "./_connectors"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

interface AddChannelModalProps {
  open: boolean
  onClose: () => void
}

function BrowseSkeleton() {
  const groups = [4, 3, 3, 2]
  return (
    <div className="space-y-6">
      {groups.map((count, gi) => (
        <div key={gi}>
          <div className="mb-3 h-3 w-24 animate-pulse rounded bg-[var(--color-surface-raised)]" />
          <div className="grid gap-3 sm:grid-cols-2">
            {Array.from({ length: count }).map((_, ci) => (
              <div
                key={ci}
                className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-4"
              >
                <div className="flex items-start gap-3">
                  <div className="h-9 w-9 shrink-0 animate-pulse rounded-xl bg-[var(--color-surface-raised)]" />
                  <div className="flex-1 space-y-2">
                    <div className="h-4 w-1/2 animate-pulse rounded bg-[var(--color-surface-raised)]" />
                    <div className="h-3 w-full animate-pulse rounded bg-[var(--color-surface-raised)]" />
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

export function AddChannelModal({ open, onClose }: AddChannelModalProps) {
  const { tier } = useLicense()
  const isEnterprise = tier === "enterprise"

  const [catalog, setCatalog] = useState<ConnectorType[]>([])
  const [catalogState, setCatalogState] = useState<"loading" | "ok" | "error">("loading")

  const [destinations, setDestinations] = useState<NotificationDestination[]>([])

  const [configuringConnector, setConfiguringConnector] = useState<ConnectorType | null>(null)
  const [activeCategory, setActiveCategory] = useState<string>("all")
  const [searchQuery, setSearchQuery] = useState<string>("")

  const loadData = useCallback(() => {
    setCatalogState("loading")
    Promise.all([
      getCatalog(),
      listDestinations(),
    ])
      .then(([cat, dests]) => {
        setCatalog(cat.connectors)
        setDestinations(dests)
        setCatalogState("ok")
      })
      .catch(() => setCatalogState("error"))
  }, [])

  // Load when modal opens
  useEffect(() => {
    if (open) {
      loadData()
    } else {
      // Reset search/filter when closing
      setActiveCategory("all")
      setSearchQuery("")
      setConfiguringConnector(null)
    }
  }, [open, loadData])

  const allConnectors = useMemo(() => {
    const liveIds = new Set(catalog.map((c) => c.id))
    return [...catalog, ...COMING_SOON_CONNECTORS.filter((c) => !liveIds.has(c.id))]
  }, [catalog])

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

  const searchMatches = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return null
    return new Set(
      allConnectors
        .filter((c) => c.name.toLowerCase().includes(q) || c.id.toLowerCase().includes(q))
        .map((c) => c.id),
    )
  }, [allConnectors, searchQuery])

  const handleDestinationCreated = useCallback((_dest: NotificationDestination) => {
    // Refresh destinations so "Connected" badges update
    listDestinations()
      .then((rows) => setDestinations(rows))
      .catch(() => {})
    setConfiguringConnector(null)
  }, [])

  return (
    <Sheet open={open} onClose={onClose} title="Add notification channel" size="xl">
      <div className="space-y-5">
        {/* Non-enterprise upgrade prompt */}
        {!isEnterprise && (
          <div className="flex items-center justify-between rounded-xl border border-[var(--color-state-dismissed-border)] bg-[var(--color-state-dismissed-subtle)] px-4 py-3">
            <div className="flex items-center gap-2">
              <span className="rounded-full bg-[var(--color-state-dismissed-subtle)] px-2.5 py-0.5 text-xs font-semibold text-[var(--color-state-dismissed)]">
                Enterprise
              </span>
              <p className="text-xs text-[var(--color-text-primary)]">
                Most connectors require an Enterprise license.
              </p>
            </div>
            <Link
              href="/settings/license"
              className="shrink-0 rounded-lg border border-[var(--color-state-dismissed-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-state-dismissed)] transition-colors hover:bg-[var(--color-state-dismissed-subtle)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
              onClick={onClose}
            >
              Upgrade
            </Link>
          </div>
        )}

        {catalogState === "loading" && <BrowseSkeleton />}

        {catalogState === "error" && (
          <div className="flex items-center gap-3 text-sm text-[var(--color-severity-high)]">
            <span>Failed to load catalog.</span>
            <Button variant="ghost" size="xs" onClick={loadData}>
              Retry
            </Button>
          </div>
        )}

        {catalogState === "ok" && (
          <>
            {/* Category filter chips + search */}
            <div className="flex flex-wrap items-center gap-2">
              <FilterChip
                label="All"
                active={activeCategory === "all"}
                count={allConnectors.length}
                onClick={() => setActiveCategory("all")}
              />
              <span aria-hidden="true" className="h-4 w-px bg-[var(--color-border)]" />
              {categories.map((cat) => (
                <FilterChip
                  key={cat.id}
                  label={cat.label}
                  active={activeCategory === cat.id}
                  count={cat.count}
                  onClick={() => setActiveCategory(cat.id)}
                />
              ))}
              <div className="ml-auto w-44">
                <Input
                  size="sm"
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search…"
                  aria-label="Search channels"
                  className="rounded-full"
                  leadingIcon={(
                    <svg
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
                  )}
                />
              </div>
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
                    No channels match{searchQuery.trim() ? ` "${searchQuery.trim()}"` : ""}.
                  </p>
                )
              }

              return sections.map(({ cat, items }) => (
                <div key={cat}>
                  <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
                    {CATEGORY_DISPLAY[cat] ?? cat}
                  </p>
                  <div className="grid gap-3 sm:grid-cols-2">
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
      </div>

      {configuringConnector && (
        <CatalogConnectorModal
          connector={configuringConnector}
          onClose={() => setConfiguringConnector(null)}
          onSaved={handleDestinationCreated}
        />
      )}
    </Sheet>
  )
}
