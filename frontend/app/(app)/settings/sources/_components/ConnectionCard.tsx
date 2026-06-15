"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import type { SourceCategory, SourceConnection } from "@/lib/shared/sources-types"
import { SOURCE_TYPE_LABELS, CATEGORY_ITEM_LABELS, SYNC_SCHEDULE_LABELS } from "@/lib/shared/sources-types"
import {
  syncSourceConnection,
  testSourceConnection,
  deleteSourceConnection,
} from "@/lib/client/sources-api"
import { ConnectionStatusBadge } from "./ConnectionStatusBadge"
import { SourceTypeLogo } from "./SourceTypeLogo"
import { Dialog } from "@/components/layout/Dialog"
import { Button } from "@/components/ui/Button"
import { timeAgo } from "@/lib/shared/time-ago"

// ─── Time helpers ─────────────────────────────────────────────────────────────

function isSyncOverdue(nextSyncAt: string | undefined): boolean {
  if (!nextSyncAt) return false
  return new Date(nextSyncAt).getTime() < Date.now()
}

// ─── Metadata pill ────────────────────────────────────────────────────────────

function MetaPill({
  children,
  warn,
}: {
  children: React.ReactNode
  warn?: boolean
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-medium leading-none ${
        warn
          ? "bg-[var(--color-state-pending-subtle)] text-[var(--color-state-pending)]"
          : "bg-[var(--color-surface-raised)] text-[var(--color-text-secondary)]"
      }`}
    >
      {children}
    </span>
  )
}

// ─── Props ────────────────────────────────────────────────────────────────────

interface ConnectionCardProps {
  connection: SourceConnection
  category: SourceCategory
  canEdit: boolean
  onRefresh: () => void
}

// ─── Component (row inside grouped card) ──────────────────────────────────────

export function ConnectionCard({
  connection,
  category,
  canEdit,
  onRefresh,
}: ConnectionCardProps) {
  const router = useRouter()
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [testResult, setTestResult] = useState<{
    success: boolean
    message: string
  } | null>(null)
  const [isSyncing, setIsSyncing] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)

  const itemLabel = CATEGORY_ITEM_LABELS[category]
  const overdue = isSyncOverdue(connection.nextSyncAt)

  // Scope: "10 of 12 repos" when exclusions, "12 repos" otherwise
  const totalItems = connection.discoveredItemCount
  const excludedCount = connection.excludedItems.length
  const hasExclusions = connection.scanScope === "all-except-excluded" && excludedCount > 0
  const scopeLabel =
    totalItems != null
      ? hasExclusions
        ? `${totalItems - excludedCount} of ${totalItems} ${itemLabel}`
        : `${totalItems} ${itemLabel}`
      : null

  function navigateToScope() {
    router.push(`/sources/${category}/${connection.id}`)
  }

  async function handleSync(e: React.MouseEvent) {
    e.stopPropagation()
    setIsSyncing(true)
    await syncSourceConnection(connection.id)
    setIsSyncing(false)
    onRefresh()
  }

  async function handleTest(e: React.MouseEvent) {
    e.stopPropagation()
    setIsTesting(true)
    const result = await testSourceConnection(connection.id)
    setIsTesting(false)
    if (result.ok) {
      setTestResult({ success: result.data.success, message: result.data.message })
    } else {
      setTestResult({ success: false, message: result.error })
    }
    onRefresh()
    setTimeout(() => setTestResult(null), 5000)
  }

  async function handleDelete() {
    setIsDeleting(true)
    await deleteSourceConnection(connection.id)
    setIsDeleting(false)
    setShowDeleteConfirm(false)
    onRefresh()
  }

  return (
    <>
      <div
        className="flex cursor-pointer items-start gap-4 px-5 py-4 transition-colors hover:bg-[var(--color-surface-raised)]"
        onClick={navigateToScope}
      >
        {/* Brand logo */}
        <SourceTypeLogo type={connection.sourceType} size={28} className="mt-0.5 shrink-0" />

        {/* Main content */}
        <div className="min-w-0 flex-1">
          {/* Top line: name + status */}
          <div className="flex items-center justify-between gap-3">
            <span className="truncate text-sm font-medium text-[var(--color-text-primary)]">
              {connection.name}
              {connection.auth.orgOrOwner && (
                <span className="ml-1.5 font-normal text-[var(--color-text-secondary)]">
                  / {connection.auth.orgOrOwner}
                </span>
              )}
            </span>
            <ConnectionStatusBadge status={connection.status} />
          </div>

          {/* Metadata pills */}
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {scopeLabel && (
              <MetaPill warn={hasExclusions}>
                {hasExclusions && (
                  <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="10" />
                    <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
                  </svg>
                )}
                {scopeLabel}
              </MetaPill>
            )}
            {connection.lastSyncedAt && (
              <MetaPill warn={overdue}>
                {overdue ? (
                  <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
                  </svg>
                ) : (
                  <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                  </svg>
                )}
                {overdue ? "Overdue" : timeAgo(connection.lastSyncedAt)}
              </MetaPill>
            )}
            <MetaPill>
              <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182M20.015 4.356v4.992" />
              </svg>
              {SYNC_SCHEDULE_LABELS[connection.syncSchedule]}
            </MetaPill>
          </div>

          {/* Test result inline */}
          {testResult && (
            <div
              className={`mt-2 inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium ${
                testResult.success
                  ? "bg-[var(--color-status-ok-subtle)] text-[var(--color-status-ok)]"
                  : "bg-[var(--color-severity-critical-subtle)] text-[var(--color-severity-critical)]"
              }`}
            >
              <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                {testResult.success ? (
                  <polyline points="20 6 9 17 4 12" />
                ) : (
                  <><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></>
                )}
              </svg>
              {testResult.message}
            </div>
          )}

          {/* Error message — only show on error status */}
          {connection.status === "error" && connection.statusMessage && !testResult && (
            <p className="mt-1.5 text-xs text-[var(--color-severity-critical)]">
              {connection.statusMessage}
            </p>
          )}

          {/* Action buttons */}
          {canEdit && (
            <div
              className="mt-3 flex flex-wrap items-center gap-2"
              onClick={(e) => e.stopPropagation()}
            >
              <Button
                variant="secondary"
                size="sm"
                disabled={isSyncing}
                isLoading={isSyncing}
                onClick={handleSync}
                className="border-[var(--color-accent)] text-[var(--color-accent)] hover:bg-[var(--color-accent-subtle)]"
              >
                {isSyncing ? "Syncing\u2026" : "Sync Now"}
              </Button>

              <Button
                variant="secondary"
                size="sm"
                disabled={isTesting}
                isLoading={isTesting}
                onClick={handleTest}
              >
                {isTesting ? "Testing\u2026" : "Test"}
              </Button>

              <Button
                variant="secondary"
                size="sm"
                onClick={(e) => {
                  e.stopPropagation()
                  navigateToScope()
                }}
              >
                Configure
              </Button>

              <Button
                variant="secondary"
                size="sm"
                onClick={(e) => {
                  e.stopPropagation()
                  setShowDeleteConfirm(true)
                }}
                className="border-[var(--color-severity-critical-border)] text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-subtle)]"
              >
                Delete
              </Button>
            </div>
          )}
        </div>
      </div>

      {/* Delete confirmation */}
      <Dialog
        open={showDeleteConfirm}
        onClose={() => setShowDeleteConfirm(false)}
        onConfirm={handleDelete}
        title="Delete connection?"
        description={`This will permanently remove "${connection.name}" and all associated scan configuration. This action cannot be undone.`}
        confirmLabel={isDeleting ? "Deleting\u2026" : "Delete"}
        variant="danger"
      />
    </>
  )
}
