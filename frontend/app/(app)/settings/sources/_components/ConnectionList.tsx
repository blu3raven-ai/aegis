"use client"

import { useEffect, useState, useCallback } from "react"
import type { SourceCategory, SourceConnection } from "@/lib/shared/sources-types"
import { CATEGORY_LABELS, CATEGORY_ITEM_LABELS } from "@/lib/shared/sources-types"
import { listSourceConnections } from "@/lib/client/source-connections-api"
import { ConnectionCard } from "./ConnectionCard"
import { AddConnectionModal } from "@/components/sources/AddConnectionModal"
import { useLicense } from "@/lib/client/license/client"
import { TIER_LABELS } from "@/lib/shared/license/types"
import type { Tier } from "@/lib/shared/license/types"
import { useSSE } from "@/components/providers/SSEProvider"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Skeleton } from "@/components/ui/Skeleton"
import type { SourceSyncedEvent } from "@/lib/shared/sse-types"


const CATEGORY_DESCRIPTIONS: Record<SourceCategory, string> = {
  "code-repositories": "Manage your code host connections and control which repositories are scanned.",
  "container-registry": "Manage your container registry connections and control which images are scanned.",
  "cloud-infrastructure": "Manage your cloud infrastructure connections and monitor your cloud resources.",
  "ci-systems": "Manage your CI system connections to trigger scans from your pipelines.",
}

const CATEGORY_EMPTY_HINTS: Record<SourceCategory, string> = {
  "code-repositories": "Add a code host connection to start discovering and scanning your repositories.",
  "container-registry": "Add a container registry connection to start discovering and scanning your images.",
  "cloud-infrastructure": "Add a cloud infrastructure connection to start monitoring your cloud resources.",
  "ci-systems": "Add a CI system connection to trigger scans from your build pipelines.",
}


function SkeletonRow() {
  return (
    <div className="flex items-center gap-4 px-5 py-4">
      <Skeleton className="h-8 w-8 shrink-0 rounded-lg" />
      <div className="flex flex-1 flex-col gap-1.5">
        <Skeleton className="h-3.5 w-36" />
        <Skeleton className="h-3 w-24" />
      </div>
      <Skeleton className="h-5 w-20 rounded-full" />
    </div>
  )
}


interface ConnectionListProps {
  category: SourceCategory
  canEdit: boolean
  initialTotalConnections?: number
}


export function ConnectionList({ category, canEdit, initialTotalConnections }: ConnectionListProps) {
  const [connections, setConnections] = useState<SourceConnection[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)
  const { tier, limits, usage, isLoading: licenseLoading } = useLicense()
  const nextTier: Tier | null = tier === "community" ? "enterprise" : null

  const maxConnections = limits.max_source_connections
  const currentConnections = licenseLoading && initialTotalConnections != null ? initialTotalConnections : usage.source_connections
  const remaining = maxConnections != null ? Math.max(0, maxConnections - currentConnections) : null
  const atLimit = maxConnections != null && currentConnections >= maxConnections

  const itemLabel = CATEGORY_ITEM_LABELS[category]

  // ── load ─────────────────────────────────────────────────────────────────────
  // silent=true skips the loading skeleton (used for background refreshes)
  const load = useCallback(async (silent = false) => {
    if (!silent) setIsLoading(true)
    setError(null)
    const result = await listSourceConnections(category)
    if (!silent) setIsLoading(false)
    if (result.ok) {
      setConnections(result.data.connections)
    } else {
      setError(result.error)
    }
  }, [category])

  useEffect(() => {
    void load()
  }, [load])

  useSSE("source.synced", (data: SourceSyncedEvent) => {
    void load(true)  // silent refresh
  })

  return (
    <div className="space-y-8">
      {/* Page header — matches Teams style */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
            {CATEGORY_LABELS[category]}
          </h2>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
            {CATEGORY_DESCRIPTIONS[category]}
          </p>
        </div>
        {canEdit && (
          <div className="flex shrink-0 flex-col items-end gap-1">
            <Button
              variant="primary"
              size="md"
              onClick={atLimit ? undefined : () => setShowAddModal(true)}
              disabled={atLimit}
              leadingIcon={
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <line x1="12" y1="5" x2="12" y2="19" />
                  <line x1="5" y1="12" x2="19" y2="12" />
                </svg>
              }
            >
              Add Connection
            </Button>
            {atLimit && nextTier && (
              <a href="/settings/license" className="text-[11px] text-[var(--color-accent)] hover:underline">
                Requires {TIER_LABELS[nextTier]} plan
              </a>
            )}
            {!atLimit && maxConnections != null && !licenseLoading && (
              <span className="text-[11px] text-[var(--color-text-secondary)]">
                {remaining} remaining
              </span>
            )}
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-4 py-3 text-sm text-[var(--color-severity-critical-text)]">
          {error}
        </div>
      )}

      {/* Loading skeleton — grouped card style */}
      {isLoading ? (
        <div>
          <p className="mb-4 text-2xs font-bold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            Connections
          </p>
          <Card padding="none" className="divide-y divide-[var(--color-border)] overflow-hidden rounded-xl">
            <SkeletonRow />
            <SkeletonRow />
          </Card>
        </div>
      ) : connections.length === 0 ? (
        /* Empty state — matches Teams empty style */
        <div className="rounded-xl border-2 border-dashed border-[var(--color-border)] px-6 py-12 text-center">
          <svg
            className="mx-auto h-10 w-10 text-[var(--color-text-secondary)]"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.5}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M13.19 8.688a4.5 4.5 0 0 1 1.242 7.244l-4.5 4.5a4.5 4.5 0 0 1-6.364-6.364l1.757-1.757m9.86-2.54a4.5 4.5 0 0 0-1.242-7.244l4.5-4.5a4.5 4.5 0 1 0-6.364 6.364L11.5 9.87" />
          </svg>
          <p className="mt-3 text-sm font-medium text-[var(--color-text-primary)]">
            No connections yet
          </p>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            {CATEGORY_EMPTY_HINTS[category]}
          </p>
          {canEdit && (
            <div className="mt-5 inline-flex">
              <Button variant="primary" size="md" onClick={() => setShowAddModal(true)}>
                Add Your First Connection
              </Button>
            </div>
          )}
        </div>
      ) : (
        /* Connections grouped in a card — matches Account section pattern */
        <div>
          <p className="mb-4 text-2xs font-bold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            Connections
          </p>
          <Card padding="none" className="divide-y divide-[var(--color-border)] overflow-hidden rounded-xl">
            {connections.map((conn) => (
              <ConnectionCard
                key={conn.id}
                connection={conn}
                category={category}
                canEdit={canEdit}
                onRefresh={load}
              />
            ))}
          </Card>
        </div>
      )}

      {/* Add connection modal */}
      {showAddModal && (
        <AddConnectionModal
          lockedCategory={category}
          onClose={() => setShowAddModal(false)}
          onCreated={() => {
            setShowAddModal(false)
            void load()
          }}
        />
      )}
    </div>
  )
}
