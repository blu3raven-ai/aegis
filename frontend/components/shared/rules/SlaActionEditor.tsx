"use client"

/**
 * Editor for the SLA action portion of a rule: a deadline (in days)
 * plus an ordered list of optional escalation steps that fire at a
 * given number of hours before the deadline by notifying a channel.
 *
 * The editor is intentionally permissive — it surfaces inline hints
 * for invalid values but the parent modal owns the final go/no-go
 * validation before submitting to the backend.
 */

import Link from "next/link"
import type { SlaAction, SlaEscalation } from "@/lib/client/rules-api"
import type { NotificationDestination } from "@/lib/client/destinations-api"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"

const MAX_ESCALATIONS = 4

interface SlaActionEditorProps {
  value: SlaAction
  destinations: NotificationDestination[]
  onChange: (next: SlaAction) => void
}

export function SlaActionEditor({ value, destinations, onChange }: SlaActionEditorProps) {
  const deadlineHours = Math.max(0, Math.floor(value.deadline_days)) * 24

  function updateDeadline(raw: string) {
    const parsed = Number.parseInt(raw, 10)
    const next = Number.isFinite(parsed) ? parsed : 0
    onChange({ ...value, deadline_days: next })
  }

  function updateEscalation(index: number, patch: Partial<SlaEscalation>) {
    const escalations = value.escalations.map((esc, i) =>
      i === index ? { ...esc, ...patch } : esc,
    )
    onChange({ ...value, escalations })
  }

  function removeEscalation(index: number) {
    const escalations = value.escalations.filter((_, i) => i !== index)
    onChange({ ...value, escalations })
  }

  function addEscalation() {
    if (value.escalations.length >= MAX_ESCALATIONS) return
    const defaultChannel = destinations[0]?.id ?? 0
    const next: SlaEscalation = { at_hours: 24, channel_id: defaultChannel }
    onChange({ ...value, escalations: [...value.escalations, next] })
  }

  const atCap = value.escalations.length >= MAX_ESCALATIONS

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

      {/* Escalations */}
      <div>
        <div className="mb-2 flex items-baseline justify-between">
          <label className="block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            Escalations (optional)
          </label>
          <span className="text-[11px] text-[var(--color-text-tertiary)]">
            {value.escalations.length} / {MAX_ESCALATIONS}
          </span>
        </div>

        {destinations.length === 0 && (
          <p className="mb-3 text-xs text-[var(--color-text-tertiary)]">
            Set up a notification destination first →{" "}
            <Link
              href="/settings/notifications"
              className="text-[var(--color-accent)] underline-offset-2 hover:underline"
            >
              Notification destinations
            </Link>
          </p>
        )}

        <div className="space-y-2">
          {value.escalations.map((esc, i) => {
            const deadlineInvalid = deadlineHours === 0
            const hoursInvalid =
              !deadlineInvalid &&
              (!Number.isInteger(esc.at_hours) ||
                esc.at_hours < 1 ||
                esc.at_hours >= deadlineHours)
            const channelInvalid =
              !Number.isInteger(esc.channel_id) ||
              esc.channel_id <= 0 ||
              !destinations.some((d) => d.id === esc.channel_id)
            return (
              <div
                key={i}
                className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm text-[var(--color-text-secondary)]">At</span>
                  <Input
                    type="number"
                    min={1}
                    step={1}
                    value={esc.at_hours}
                    onChange={(e) => {
                      const parsed = Number.parseInt(e.target.value, 10)
                      updateEscalation(i, {
                        at_hours: Number.isFinite(parsed) ? parsed : 0,
                      })
                    }}
                    invalid={hoursInvalid}
                    aria-label={`Escalation ${i + 1} hours`}
                    className="w-24"
                  />
                  <span className="text-sm text-[var(--color-text-secondary)]">
                    hours → notify
                  </span>
                  <Select
                    value={esc.channel_id || ""}
                    onChange={(e) =>
                      updateEscalation(i, { channel_id: Number(e.target.value) })
                    }
                    invalid={channelInvalid}
                    aria-label={`Escalation ${i + 1} channel`}
                    className="max-w-[18rem] flex-1"
                  >
                    <option value="">— select channel —</option>
                    {destinations.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name} ({d.destination_type})
                      </option>
                    ))}
                  </Select>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => removeEscalation(i)}
                    className="ml-auto"
                  >
                    Remove
                  </Button>
                </div>
                <p
                  className={`mt-1 text-[11px] ${
                    hoursInvalid
                      ? "text-[var(--color-severity-critical)]"
                      : "text-[var(--color-text-tertiary)]"
                  }`}
                >
                  {deadlineInvalid
                    ? "Fix the deadline above first"
                    : `Must be less than the deadline (${deadlineHours} hours)`}
                </p>
              </div>
            )
          })}
        </div>

        <Button
          variant="secondary"
          size="sm"
          onClick={addEscalation}
          disabled={atCap}
          className="mt-3 border-dashed"
        >
          + Add escalation step
        </Button>
      </div>
    </div>
  )
}
