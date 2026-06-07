"use client"

import { useCallback, useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import type { SourceCategory, SourceConnection } from "@/lib/shared/sources-types"
import { CATEGORY_LABELS, CATEGORY_ITEM_LABELS, CATEGORY_API_SLUGS } from "@/lib/shared/sources-types"
import { listSourceConnections } from "@/lib/client/sources-api"
import { SourceKpiStrip } from "./SourceKpiStrip"
import { SourceConnectionCard } from "./SourceConnectionCard"
import { AddConnectionModal } from "@/app/(app)/settings/sources/_components/AddConnectionModal"
import { PageHeader } from "@/components/layout/PageHeader"
import { PoweredToolsSection } from "./PoweredToolsSection"

// ─── Empty State ──────────────────────────────────────────────────────────────

function EmptyState({
  category,
  icon,
  canEdit,
  onAdd,
}: {
  category: SourceCategory
  icon: React.ReactNode
  canEdit: boolean
  onAdd: () => void
}) {
  const itemLabel = CATEGORY_ITEM_LABELS[category]
  return (
    <div className="py-8">
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-8 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
        <div className="mx-auto max-w-md text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--color-accent)]/10">
            {icon}
          </div>
          <h3 className="mt-4 text-base font-semibold text-[var(--color-text-primary)]">No Connections Yet</h3>
          <p className="mt-1.5 text-sm text-[var(--color-text-secondary)]">
            Sources are where Aegis discovers your {itemLabel}. Connect your provider below, and Aegis will
            automatically find and scan them for vulnerabilities, exposed secrets, and code issues.
          </p>
          {canEdit && (
            <button
              type="button"
              onClick={onAdd}
              className="mt-5 inline-flex items-center gap-2 rounded-xl bg-[var(--color-accent)] px-5 py-2.5 text-sm font-semibold text-[var(--color-accent-on)] transition-opacity hover:opacity-90 focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
            >
              <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 4.5v15m7.5-7.5h-15" />
              </svg>
              Add Connection
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Loading Skeleton ─────────────────────────────────────────────────────────

function LoadingSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-28 motion-safe:animate-pulse rounded-xl bg-[var(--color-surface-raised)]" />
        ))}
      </div>
      <div className="h-20 motion-safe:animate-pulse rounded-2xl bg-[var(--color-surface-raised)]" />
    </div>
  )
}

// ─── Props ────────────────────────────────────────────────────────────────────

interface SourcePageShellProps {
  category: SourceCategory
  canEdit: boolean
  icon: React.ReactNode
  /** When false, the internal PageHeader is omitted (caller provides chrome). */
  showHeader?: boolean
  /** Caller-controlled modal open state — used when the trigger button lives in the parent header. */
  controlledShowAdd?: boolean
  onControlledShowAddChange?: (open: boolean) => void
}

// ─── Component ────────────────────────────────────────────────────────────────

export function SourcePageShell({
  category,
  canEdit,
  icon,
  showHeader = true,
  controlledShowAdd,
  onControlledShowAddChange,
}: SourcePageShellProps) {
  const router = useRouter()
  const [connections, setConnections] = useState<SourceConnection[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [internalShowAdd, setInternalShowAdd] = useState(false)

  // When the caller controls the modal (header button pattern), use its state; otherwise use internal.
  const showAddModal = controlledShowAdd !== undefined ? controlledShowAdd : internalShowAdd
  const setShowAddModal = controlledShowAdd !== undefined
    ? (open: boolean) => onControlledShowAddChange?.(open)
    : setInternalShowAdd

  const categorySlug = CATEGORY_API_SLUGS[category]
  const title = CATEGORY_LABELS[category]

  const CATEGORY_DESCRIPTIONS: Record<SourceCategory, string> = {
    "code-repositories": "Connect code hosts to scan repositories for vulnerabilities, secrets, and code issues.",
    "container-registry": "Connect container registries to scan images for vulnerabilities.",
    "cloud-infrastructure": "Connect cloud accounts for infrastructure security scanning.",
  }
  const description = CATEGORY_DESCRIPTIONS[category]

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError(false)
    try {
      const result = await listSourceConnections(categorySlug as SourceCategory)
      if (result.ok) {
        setConnections(result.data.connections)
      } else {
        setLoadError(true)
      }
    } catch {
      setLoadError(true)
    }
    setLoading(false)
  }, [categorySlug])

  useEffect(() => {
    void load()
  }, [load])

  function handleEdit(connection: SourceConnection) {
    router.push(`/sources/${category}/${connection.id}`)
  }

  return (
    <>
      {/* Shared PageHeader — matches tool dashboards. Suppressed when the caller renders its own chrome (e.g. /sources tabs). */}
      {showHeader && (
        <PageHeader
          icon={icon}
          title={title}
          description={description}
          controls={
            canEdit ? (
              <button
                type="button"
                onClick={() => setShowAddModal(true)}
                className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
              >
                Add Connection
              </button>
            ) : undefined
          }
        />
      )}

      {/* Main Content */}
      <main className="mx-auto max-w-7xl space-y-5 px-6 py-8">
        {loading ? (
          <LoadingSkeleton />
        ) : loadError ? (
          <div className="flex items-center justify-between rounded-2xl border border-[var(--color-severity-high)]/20 bg-[var(--color-severity-high)]/5 px-5 py-3">
            <span className="text-sm text-[var(--color-text-primary)]">Failed to load connections.</span>
            <button
              type="button"
              onClick={() => void load()}
              className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
            >
              Retry
            </button>
          </div>
        ) : connections.length === 0 ? (
          <EmptyState
            category={category}
            icon={icon}
            canEdit={canEdit}
            onAdd={() => setShowAddModal(true)}
          />
        ) : (
          <>
            <SourceKpiStrip connections={connections} />

            {/* Connection list */}
            <div className="space-y-3">
              {connections.map((connection) => (
                <SourceConnectionCard
                  key={connection.id}
                  connection={connection}
                  category={category}
                  onSync={load}
                  onEdit={() => handleEdit(connection)}
                  onDelete={load}
                />
              ))}
            </div>

            {/* Powered tools */}
            <PoweredToolsSection category={category} hasConnections={connections.length > 0} />
          </>
        )}

        {/* Show powered tools even on empty state — shows what connecting enables */}
        {!loading && connections.length === 0 && (
          <PoweredToolsSection category={category} hasConnections={false} />
        )}
      </main>

      {/* Add Connection Modal */}
      {showAddModal && (
        <AddConnectionModal
          category={category}
          onClose={() => setShowAddModal(false)}
          onCreated={() => {
            setShowAddModal(false)
            void load()
          }}
        />
      )}
    </>
  )
}
