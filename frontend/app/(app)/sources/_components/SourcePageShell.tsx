"use client"

import { useCallback, useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import type { SourceCategory, SourceConnection } from "@/lib/shared/sources-types"
import { CATEGORY_LABELS, CATEGORY_ITEM_LABELS, CATEGORY_API_SLUGS } from "@/lib/shared/sources-types"
import { listSourceConnections } from "@/lib/client/source-connections-api"
import { SourceKpiStrip } from "./SourceKpiStrip"
import { SourceConnectionCard } from "./SourceConnectionCard"
import { AddConnectionModal } from "@/components/sources/AddConnectionModal"
import { PageHeader } from "@/components/layout/PageHeader"
import { Skeleton } from "@/components/ui/Skeleton"
import { PoweredToolsSection } from "./PoweredToolsSection"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"


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
      <Card padding="none" className="rounded-2xl p-8 shadow-[0_28px_80px_rgba(15,23,42,0.06)]">
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
            <div className="mt-5 inline-flex">
              <Button
                variant="primary"
                size="md"
                onClick={onAdd}
                leadingIcon={
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M12 4.5v15m7.5-7.5h-15" />
                  </svg>
                }
              >
                Add Connection
              </Button>
            </div>
          )}
        </div>
      </Card>
    </div>
  )
}


function LoadingSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-28 rounded-xl" />
        ))}
      </div>
      <Skeleton className="h-20 rounded-2xl" />
    </div>
  )
}


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
    "ci-systems": "Connect CI systems to trigger scans from your build pipelines.",
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
              <Button variant="primary" size="md" onClick={() => setShowAddModal(true)}>
                Add Connection
              </Button>
            ) : undefined
          }
        />
      )}

      {/* Main Content */}
      <main className="space-y-5 px-6 py-8">
        {loading ? (
          <LoadingSkeleton />
        ) : loadError ? (
          <div className="flex items-center justify-between rounded-2xl border border-[var(--color-severity-high)]/20 bg-[var(--color-severity-high)]/5 px-5 py-3">
            <span className="text-sm text-[var(--color-text-primary)]">Failed to load connections.</span>
            <Button variant="secondary" size="sm" onClick={() => void load()}>
              Retry
            </Button>
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
          lockedCategory={category}
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
