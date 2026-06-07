"use client"

/**
 * Modal for creating and editing notification routing rules.
 *
 * Renders a form with name, channel selector, priority, enabled toggle,
 * and the ConditionBuilder recursive tree editor.
 */

import { useEffect, useState } from "react"
import type {
  Condition,
  CreateRulePayload,
  NotificationRule,
} from "@/lib/client/notification-rules-api"
import type { NotificationDestination } from "@/lib/client/destinations-api"
import { ConditionBuilder } from "@/components/shared/rules-engine/ConditionBuilder"
import { NOTIFICATION_ROUTING_FIELDS } from "@/lib/rules-engine/field-schemas"

interface RuleEditorModalProps {
  open: boolean
  rule: NotificationRule | null   // null = create mode
  destinations: NotificationDestination[]
  orgId: string
  onClose: () => void
  onSave: (payload: CreateRulePayload) => Promise<void>
  saving?: boolean
  saveError?: string | null
}

export function RuleEditorModal({
  open,
  rule,
  destinations,
  orgId,
  onClose,
  onSave,
  saving,
  saveError,
}: RuleEditorModalProps) {
  const [name, setName] = useState("")
  const [channelId, setChannelId] = useState<number | "">("")
  const [priority, setPriority] = useState(100)
  const [enabled, setEnabled] = useState(true)
  const [conditions, setConditions] = useState<Condition>({ all: [] })

  // Populate from existing rule when editing
  useEffect(() => {
    if (rule) {
      setName(rule.name)
      setChannelId(rule.channel_id)
      setPriority(rule.priority)
      setEnabled(rule.enabled)
      setConditions(rule.conditions)
    } else {
      setName("")
      setChannelId(destinations[0]?.id ?? "")
      setPriority(100)
      setEnabled(true)
      setConditions({ all: [] })
    }
  }, [rule, open])

  if (!open) return null

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!channelId) return

    await onSave({
      org_id: orgId,
      name,
      channel_id: channelId as number,
      conditions,
      priority,
      enabled,
    })
  }

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-[var(--color-overlay)]"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal */}
      <div
        role="dialog"
        aria-modal="true"
        aria-label={rule ? "Edit routing rule" : "New routing rule"}
        className="fixed left-1/2 top-1/2 z-50 w-full max-w-2xl -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] shadow-2xl"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-6 py-4">
          <h2 className="text-sm font-semibold text-[var(--color-text-primary)]">
            {rule ? "Edit rule" : "New routing rule"}
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="close"
            className="rounded p-1 text-[var(--color-text-tertiary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
          >
            ×
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="overflow-y-auto max-h-[75vh]">
          <div className="space-y-5 px-6 py-5">

            {/* Name */}
            <div>
              <label
                htmlFor="rule-name"
                className="block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)] mb-1"
              >
                Rule name
              </label>
              <input
                id="rule-name"
                type="text"
                required
                maxLength={120}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Crits to #sec-incidents"
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-accent)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
              />
            </div>

            {/* Channel */}
            <div>
              <label
                htmlFor="rule-channel"
                className="block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)] mb-1"
              >
                Channel
              </label>
              <select
                id="rule-channel"
                required
                value={channelId}
                onChange={(e) => setChannelId(Number(e.target.value))}
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
              >
                <option value="">— select channel —</option>
                {destinations.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name} ({d.destination_type})
                  </option>
                ))}
              </select>
              {destinations.length === 0 && (
                <p className="mt-1 text-xs text-[var(--color-text-tertiary)]">
                  No destinations configured. Add one in Notification destinations first.
                </p>
              )}
            </div>

            {/* Priority + Enabled */}
            <div className="flex items-end gap-4">
              <div className="flex-1">
                <label
                  htmlFor="rule-priority"
                  className="block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)] mb-1"
                >
                  Priority
                </label>
                <input
                  id="rule-priority"
                  type="number"
                  min={0}
                  value={priority}
                  onChange={(e) => setPriority(Math.max(0, Number(e.target.value)))}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
                />
                <p className="mt-1 text-[11px] text-[var(--color-text-tertiary)]">
                  Lower = higher priority. First match wins.
                </p>
              </div>

              <div className="pb-5">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={(e) => setEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-[var(--color-border)] accent-[var(--color-accent)]"
                  />
                  <span className="text-sm text-[var(--color-text-primary)]">Enabled</span>
                </label>
              </div>
            </div>

            {/* Conditions */}
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)] mb-2">
                Conditions
              </label>
              <p className="mb-2 text-xs text-[var(--color-text-tertiary)]">
                An empty condition matches every finding (catch-all).
              </p>
              <ConditionBuilder value={conditions} onChange={setConditions} fields={NOTIFICATION_ROUTING_FIELDS} />
            </div>

            {/* Error */}
            {saveError && (
              <p className="text-sm text-[var(--color-severity-critical)]">{saveError}</p>
            )}
          </div>

          {/* Footer */}
          <div className="flex justify-end gap-3 border-t border-[var(--color-border)] px-6 py-4">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)]"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !channelId}
              className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)] disabled:opacity-60"
            >
              {saving ? "Saving…" : rule ? "Save changes" : "Create rule"}
            </button>
          </div>
        </form>
      </div>
    </>
  )
}
