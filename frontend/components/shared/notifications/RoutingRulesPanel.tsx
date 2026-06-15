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
import { Button } from "@/components/ui/Button"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { Table, Thead, Tbody, Tr, Th, Td } from "@/components/ui/Table"

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
    <Tr>
      {[1, 2, 3, 4, 5].map((i) => (
        <Td key={i}>
          <div className="h-4 w-full animate-pulse rounded bg-[var(--color-surface-raised)]" />
        </Td>
      ))}
    </Tr>
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
          <Button variant="primary" size="md" onClick={openCreate} className="shrink-0">
            New rule
          </Button>
        )}
      </div>

      {/* Tabs */}
      <SegmentedControl
        ariaLabel="Notification routing view"
        value={activeTab}
        onChange={setActiveTab}
        options={[
          { id: "rules",   label: "Rules" },
          { id: "preview", label: "Preview" },
        ]}
      />

      {/* Error state */}
      {loadError && (
        <div className="rounded-2xl border border-[var(--color-border-strong)] bg-[var(--color-surface)] p-8">
          <p className="text-sm font-semibold text-[var(--color-severity-critical)]">
            Couldn&apos;t load rules
          </p>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{loadError}</p>
          <div className="mt-4">
            <Button variant="secondary" size="md" onClick={loadAll}>
              Retry
            </Button>
          </div>
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
              <div className="mt-4 inline-flex">
                <Button variant="primary" size="md" onClick={openCreate}>
                  Create first rule
                </Button>
              </div>
            </div>
          ) : (
            <div className="overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)]">
              <Table>
                <Thead>
                  <Tr>
                    {["Priority", "Name", "Channel", "Enabled", "Updated", "Actions"].map((h) => (
                      <Th key={h}>{h}</Th>
                    ))}
                  </Tr>
                </Thead>
                <Tbody>
                  {loading ? (
                    <>
                      <SkeletonRow />
                      <SkeletonRow />
                      <SkeletonRow />
                    </>
                  ) : (
                    rules.map((rule) => (
                      <Tr key={rule.id} interactive>
                        {/* Priority */}
                        <Td className="tabular-nums text-[var(--color-text-tertiary)] text-xs">
                          {rule.priority}
                        </Td>
                        {/* Name */}
                        <Td className="font-medium text-[var(--color-text-primary)]">
                          {rule.name}
                        </Td>
                        {/* Channel */}
                        <Td className="text-[var(--color-text-secondary)] text-xs">
                          {destName(rule.channel_id)}
                        </Td>
                        {/* Enabled toggle */}
                        <Td>
                          <Button
                            variant="ghost"
                            size="xs"
                            onClick={() => handleToggle(rule)}
                            aria-label={rule.enabled ? "disable rule" : "enable rule"}
                            className={
                              rule.enabled
                                ? "bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok)] hover:bg-[var(--color-status-ok)]/10 hover:text-[var(--color-status-ok)]"
                                : "bg-[var(--color-border)] text-[var(--color-text-tertiary)] hover:bg-[var(--color-border)] hover:text-[var(--color-text-tertiary)]"
                            }
                            leadingIcon={
                              <span
                                className={`h-1.5 w-1.5 rounded-full ${
                                  rule.enabled
                                    ? "bg-[var(--color-status-ok)]"
                                    : "bg-[var(--color-text-tertiary)]"
                                }`}
                                aria-hidden="true"
                              />
                            }
                          >
                            {rule.enabled ? "On" : "Off"}
                          </Button>
                        </Td>
                        {/* Updated */}
                        <Td className="text-[var(--color-text-tertiary)] text-xs">
                          {relativeTime(rule.updated_at)}
                        </Td>
                        {/* Actions */}
                        <Td>
                          <div className="flex items-center gap-2">
                            <Button
                              variant="ghost"
                              size="xs"
                              onClick={() => openEdit(rule)}
                              className="text-[var(--color-accent)] hover:bg-[var(--color-accent-subtle)] hover:text-[var(--color-accent)]"
                            >
                              Edit
                            </Button>
                            <Button
                              variant="ghost"
                              size="xs"
                              onClick={() => handleDelete(rule)}
                              className="text-[var(--color-severity-critical)] hover:bg-[var(--color-severity-critical-subtle)] hover:text-[var(--color-severity-critical)]"
                            >
                              Delete
                            </Button>
                          </div>
                        </Td>
                      </Tr>
                    ))
                  )}
                </Tbody>
              </Table>
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
