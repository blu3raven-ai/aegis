"use client"

/**
 * Full routing rules panel: rules table + editor modal + preview pane.
 *
 * Encapsulates all state so the page component stays minimal.
 */

import { useCallback, useEffect, useState } from "react"
import type { NotificationRule, CreateRulePayload } from "@/lib/client/notification-rules-api"
import { listRules, createRule, updateRule, deleteRule } from "@/lib/client/notification-rules-api"
import type { NotificationDestination } from "@/lib/client/destinations-api"
import { listDestinations } from "@/lib/client/destinations-api"
import { RuleEditorModal } from "./RuleEditorModal"
import { RulePreview } from "./RulePreview"

interface RoutingRulesPanelProps {
  orgId: string
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function SkeletonRow() {
  return (
    <tr>
      {[1, 2, 3, 4, 5].map((i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 w-full animate-pulse rounded bg-[var(--color-surface-raised)]" />
        </td>
      ))}
    </tr>
  )
}

export function RoutingRulesPanel({ orgId }: RoutingRulesPanelProps) {
  const [rules, setRules] = useState<NotificationRule[]>([])
  const [destinations, setDestinations] = useState<NotificationDestination[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)

  const [activeTab, setActiveTab] = useState<"rules" | "preview">("rules")

  // Editor modal
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<NotificationRule | null>(null)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  const loadAll = useCallback(() => {
    setLoading(true)
    setLoadError(null)
    Promise.all([listRules(orgId), listDestinations(orgId)])
      .then(([r, d]) => {
        setRules(r)
        setDestinations(d)
      })
      .catch((err: Error) => setLoadError(err.message))
      .finally(() => setLoading(false))
  }, [orgId])

  useEffect(() => {
    loadAll()
  }, [loadAll])

  function openCreate() {
    setEditing(null)
    setSaveError(null)
    setModalOpen(true)
  }

  function openEdit(rule: NotificationRule) {
    setEditing(rule)
    setSaveError(null)
    setModalOpen(true)
  }

  async function handleSave(payload: CreateRulePayload) {
    setSaving(true)
    setSaveError(null)
    try {
      if (editing) {
        const updated = await updateRule(editing.id, orgId, payload)
        setRules((prev) => prev.map((r) => (r.id === updated.id ? updated : r)))
      } else {
        const created = await createRule(payload)
        setRules((prev) => [...prev, created].sort((a, b) => a.priority - b.priority))
      }
      setModalOpen(false)
    } catch (err: unknown) {
      setSaveError(err instanceof Error ? err.message : "Save failed")
    } finally {
      setSaving(false)
    }
  }

  async function handleToggle(rule: NotificationRule) {
    try {
      const updated = await updateRule(rule.id, orgId, { enabled: !rule.enabled })
      setRules((prev) => prev.map((r) => (r.id === updated.id ? updated : r)))
    } catch {
      // Silently ignore — the toggle reverts visually on next load
    }
  }

  async function handleDelete(rule: NotificationRule) {
    if (!window.confirm(`Delete rule "${rule.name}"? This cannot be undone.`)) return
    try {
      await deleteRule(rule.id, orgId)
      setRules((prev) => prev.filter((r) => r.id !== rule.id))
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : "Delete failed")
    }
  }

  function destName(channelId: number): string {
    return destinations.find((d) => d.id === channelId)?.name ?? `channel ${channelId}`
  }

  return (
    <div className="space-y-6">
      {/* Panel header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-[var(--color-text-primary)]">
            Notification routing
          </h2>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
            Send findings to the right channel based on rules. Rules evaluate in
            priority order — the first match wins.
          </p>
        </div>
        {!loading && !loadError && (
          <button
            type="button"
            onClick={openCreate}
            className="shrink-0 rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)]"
          >
            + New rule
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-0.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-0.5 w-fit">
        {(["rules", "preview"] as const).map((tab) => (
          <button
            key={tab}
            type="button"
            onClick={() => setActiveTab(tab)}
            className={`rounded-md px-4 py-1.5 text-xs font-semibold capitalize transition-colors ${
              activeTab === tab
                ? "bg-[var(--color-surface)] text-[var(--color-text-primary)] shadow-sm"
                : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            {tab === "rules" ? "Rules" : "Preview"}
          </button>
        ))}
      </div>

      {/* Error state */}
      {loadError && (
        <div className="rounded-2xl border border-[var(--color-border-strong)] bg-[var(--color-surface)] p-8">
          <p className="text-sm font-semibold text-[var(--color-severity-critical)]">
            Couldn&apos;t load rules
          </p>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{loadError}</p>
          <button
            type="button"
            onClick={loadAll}
            className="mt-4 rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)]"
          >
            Retry
          </button>
        </div>
      )}

      {/* Rules tab */}
      {!loadError && activeTab === "rules" && (
        <>
          {!loading && rules.length === 0 ? (
            <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-10 text-center">
              <p className="text-sm font-semibold text-[var(--color-text-primary)]">No routing rules</p>
              <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
                All findings go to every enabled destination. Create a rule to route specific
                findings to specific channels.
              </p>
              <button
                type="button"
                onClick={openCreate}
                className="mt-4 rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)]"
              >
                Create first rule
              </button>
            </div>
          ) : (
            <div className="overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)]">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--color-border)]">
                    {["Priority", "Name", "Channel", "Enabled", "Updated", "Actions"].map((h) => (
                      <th
                        key={h}
                        className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--color-border-divider)]">
                  {loading ? (
                    <>
                      <SkeletonRow />
                      <SkeletonRow />
                      <SkeletonRow />
                    </>
                  ) : (
                    rules.map((rule) => (
                      <tr key={rule.id} className="hover:bg-[var(--color-bg-hover)] transition-colors">
                        {/* Priority */}
                        <td className="px-4 py-3 tabular-nums text-[var(--color-text-tertiary)] text-xs">
                          {rule.priority}
                        </td>
                        {/* Name */}
                        <td className="px-4 py-3 font-medium text-[var(--color-text-primary)]">
                          {rule.name}
                        </td>
                        {/* Channel */}
                        <td className="px-4 py-3 text-[var(--color-text-secondary)] text-xs">
                          {destName(rule.channel_id)}
                        </td>
                        {/* Enabled toggle */}
                        <td className="px-4 py-3">
                          <button
                            type="button"
                            onClick={() => handleToggle(rule)}
                            aria-label={rule.enabled ? "disable rule" : "enable rule"}
                            className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold ${
                              rule.enabled
                                ? "bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok)]"
                                : "bg-[var(--color-border)] text-[var(--color-text-tertiary)]"
                            }`}
                          >
                            <span
                              className={`h-1.5 w-1.5 rounded-full ${
                                rule.enabled
                                  ? "bg-[var(--color-status-ok)]"
                                  : "bg-[var(--color-text-tertiary)]"
                              }`}
                              aria-hidden="true"
                            />
                            {rule.enabled ? "On" : "Off"}
                          </button>
                        </td>
                        {/* Updated */}
                        <td className="px-4 py-3 text-[var(--color-text-tertiary)] text-xs">
                          {relativeTime(rule.updated_at)}
                        </td>
                        {/* Actions */}
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <button
                              type="button"
                              onClick={() => openEdit(rule)}
                              className="rounded px-2 py-1 text-xs font-medium text-[var(--color-accent)] hover:bg-[var(--color-accent)]/10"
                            >
                              Edit
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDelete(rule)}
                              className="rounded px-2 py-1 text-xs font-medium text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical)]/10"
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          {!loading && !loadError && rules.length > 0 && (
            <p className="text-[11px] text-[var(--color-text-tertiary)]">
              Rules execute in priority order. If no rule matches a finding, notifications
              fall back to all enabled destinations.
            </p>
          )}
        </>
      )}

      {/* Preview tab */}
      {!loadError && activeTab === "preview" && (
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6">
          <RulePreview orgId={orgId} />
        </div>
      )}

      {/* Editor modal */}
      <RuleEditorModal
        open={modalOpen}
        rule={editing}
        destinations={destinations}
        orgId={orgId}
        onClose={() => setModalOpen(false)}
        onSave={handleSave}
        saving={saving}
        saveError={saveError}
      />
    </div>
  )
}
