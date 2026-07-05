"use client"

/**
 * Editor for the SLA action portion of a rule: a deadline (in days).
 *
 * Escalations (notifying a channel before the deadline) are a coming-soon
 * action leg — they persist but never deliver — so the editor no longer lets
 * users add or edit them; any grandfathered escalations render read-only.
 *
 * The editor is intentionally permissive — it surfaces inline hints for
 * invalid values but the parent modal owns the final go/no-go validation
 * before submitting to the backend.
 */

import type { SlaAction } from "@/lib/client/rules-api"
import type { NotificationDestination } from "@/lib/client/destinations-api"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"

interface SlaActionEditorProps {
  value: SlaAction
  destinations: NotificationDestination[]
  onChange: (next: SlaAction) => void
}

export function SlaActionEditor({ value, destinations, onChange }: SlaActionEditorProps) {
  function updateDeadline(raw: string) {
    const parsed = Number.parseInt(raw, 10)
    const next = Number.isFinite(parsed) ? parsed : 0
    onChange({ ...value, deadline_days: next })
  }

  return (
    <div className="space-y-5">
      {/* Deadline */}
      <FormField label="Deadline" htmlFor="sla-deadline">
        <div className="flex items-center gap-2">
          <span className="text-sm text-[var(--color-text-secondary)]">Fix within</span>
          <Input
            id="sla-deadline"
            type="number"
            min={1}
            step={1}
            value={value.deadline_days}
            onChange={(e) => updateDeadline(e.target.value)}
            invalid={!(Number.isInteger(value.deadline_days) && value.deadline_days >= 1)}
            className="w-24"
          />
          <span className="text-sm text-[var(--color-text-secondary)]">days</span>
        </div>
      </FormField>

      {/* Escalations — coming soon */}
      <div>
        <div className="mb-2 flex items-center gap-2">
          <label className="block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            Escalations
          </label>
          <span className="rounded bg-[var(--color-surface-raised)] px-1.5 py-0.5 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
            Coming soon
          </span>
        </div>
        <p className="text-xs text-[var(--color-text-secondary)]">
          Escalating to a notification channel before the deadline isn’t wired up yet. The
          deadline above still opens a violation when it’s breached.
        </p>

        {value.escalations.length > 0 && (
          <ul className="mt-3 space-y-1.5">
            {value.escalations.map((esc, i) => {
              const channel = destinations.find((d) => d.id === esc.channel_id)
              return (
                <li
                  key={i}
                  className="flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2 text-xs text-[var(--color-text-tertiary)]"
                >
                  <span>
                    At {esc.at_hours}h before deadline → {channel ? channel.name : "a channel"}
                  </span>
                  <span className="ml-auto italic">paused</span>
                </li>
              )
            })}
          </ul>
        )}
      </div>
    </div>
  )
}
