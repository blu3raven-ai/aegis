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
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"

interface RuleEditorModalProps {
  open: boolean
  rule: NotificationRule | null   // null = create mode
  destinations: NotificationDestination[]
  onClose: () => void
  onSave: (payload: CreateRulePayload) => Promise<void>
  saving?: boolean
  saveError?: string | null
}

export function RuleEditorModal({
  open,
  rule,
  destinations,
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
          <Button
            variant="ghost"
            size="sm"
            iconOnly
            onClick={onClose}
            aria-label="close"
          >
            ×
          </Button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="overflow-y-auto max-h-[75vh]">
          <div className="space-y-5 px-6 py-5">

            {/* Name */}
            <FormField label="Rule name" htmlFor="rule-name" required>
              <Input
                id="rule-name"
                type="text"
                required
                maxLength={120}
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Crits to #sec-incidents"
              />
            </FormField>

            {/* Channel */}
            <FormField
              label="Channel"
              htmlFor="rule-channel"
              required
              hint={destinations.length === 0 ? "No destinations configured. Add one in Notification destinations first." : undefined}
            >
              <Select
                id="rule-channel"
                required
                value={channelId}
                onChange={(e) => setChannelId(Number(e.target.value))}
              >
                <option value="">— select channel —</option>
                {destinations.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name} ({d.destination_type})
                  </option>
                ))}
              </Select>
            </FormField>

            {/* Priority + Enabled */}
            <div className="flex items-end gap-4">
              <FormField
                label="Priority"
                htmlFor="rule-priority"
                hint="Lower = higher priority. First match wins."
                className="flex-1"
              >
                <Input
                  id="rule-priority"
                  type="number"
                  min={0}
                  value={priority}
                  onChange={(e) => setPriority(Math.max(0, Number(e.target.value)))}
                />
              </FormField>

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
              <label className="block text-[11px] font-mono font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)] mb-2">
                Conditions
              </label>
              <p className="mb-2 text-xs text-[var(--color-text-tertiary)]">
                An empty condition matches every finding (catch-all).
              </p>
              <ConditionBuilder value={conditions} onChange={setConditions} fields={NOTIFICATION_ROUTING_FIELDS} />
            </div>

            {/* Error */}
            {saveError && (
              <p className="text-sm text-[var(--color-severity-critical-text)]">{saveError}</p>
            )}
          </div>

          {/* Footer */}
          <div className="flex justify-end gap-3 border-t border-[var(--color-border)] px-6 py-4">
            <Button
              variant="secondary"
              size="md"
              onClick={onClose}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="md"
              disabled={saving || !channelId}
              isLoading={saving}
            >
              {saving ? "Saving…" : rule ? "Save changes" : "Create rule"}
            </Button>
          </div>
        </form>
      </div>
    </>
  )
}
