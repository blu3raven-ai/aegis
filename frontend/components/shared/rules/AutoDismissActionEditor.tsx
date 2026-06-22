"use client"

/**
 * Editor for the auto-dismiss action portion of a rule. Captures the
 * user-facing dismissal reason, an optional internal audit note, and
 * the safety-net rate alarm thresholds (% of findings dismissed within
 * a rolling minute window) that auto-disable the rule.
 *
 * Like the SLA / Scanner-coverage editors this is permissive: it
 * surfaces inline hints for invalid values but the parent modal owns
 * the final go/no-go validation before submit.
 */

import type { AutoDismissAction } from "@/lib/client/rules-api"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Textarea } from "@/components/ui/Textarea"

export const AUTO_DISMISS_DEFAULT: AutoDismissAction = {
  reason: "",
  audit_note: "",
  rate_alarm_pct: 50,
  rate_alarm_window_minutes: 60,
}

interface AutoDismissActionEditorProps {
  value: AutoDismissAction
  onChange: (next: AutoDismissAction) => void
}

export function AutoDismissActionEditor({ value, onChange }: AutoDismissActionEditorProps) {
  const reasonLen = value.reason.length
  const reasonInvalid = reasonLen < 3 || reasonLen > 200
  const auditNoteLen = (value.audit_note ?? "").length
  const auditNoteInvalid = auditNoteLen > 500
  const pctInvalid = !(
    Number.isFinite(value.rate_alarm_pct) &&
    value.rate_alarm_pct >= 1 &&
    value.rate_alarm_pct <= 100
  )
  const windowInvalid = !(
    Number.isInteger(value.rate_alarm_window_minutes) &&
    value.rate_alarm_window_minutes >= 5 &&
    value.rate_alarm_window_minutes <= 10080
  )

  return (
    <div className="space-y-5">
      <FormField
        label="User-facing dismiss reason"
        htmlFor="auto-dismiss-reason"
        labelSuffix={`${reasonLen} / 200`}
        hint={reasonInvalid ? undefined : "Shown to anyone reviewing the auto-dismissed finding."}
        error={reasonInvalid ? "Reason must be between 3 and 200 characters." : undefined}
      >
        <Textarea
          id="auto-dismiss-reason"
          value={value.reason}
          onChange={(e) => onChange({ ...value, reason: e.target.value })}
          placeholder="Auto-dismissed: test fixtures excluded"
          invalid={reasonInvalid}
          maxLength={200}
          className="min-h-[72px]"
        />
      </FormField>

      <FormField
        label={<>Audit note <span className="font-normal text-[var(--color-text-tertiary)]">(internal, optional)</span></>}
        htmlFor="auto-dismiss-audit-note"
        labelSuffix={`${auditNoteLen} / 500`}
        hint={auditNoteInvalid ? undefined : "Visible only to admins reviewing rule history."}
        error={auditNoteInvalid ? "Audit note must be 500 characters or fewer." : undefined}
      >
        <Textarea
          id="auto-dismiss-audit-note"
          value={value.audit_note ?? ""}
          onChange={(e) => onChange({ ...value, audit_note: e.target.value })}
          placeholder="Hides findings from **/test/** trees"
          invalid={auditNoteInvalid}
          maxLength={500}
          className="min-h-[72px]"
        />
      </FormField>

      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
        <div className="mb-3">
          <h4 className="text-base font-semibold text-[var(--color-text-primary)]">
            Rate alarm <span className="text-xs font-normal text-[var(--color-text-secondary)]">(safety net)</span>
          </h4>
          <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
            If this rule dismisses more than X% of findings within Y minutes, it will
            automatically disable itself and send a notification.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-sm text-[var(--color-text-secondary)]">
          <span>Disable this rule if it dismisses more than</span>
          <Input
            id="auto-dismiss-rate-pct"
            type="number"
            min={1}
            max={100}
            step={1}
            value={value.rate_alarm_pct}
            onChange={(e) => {
              const parsed = Number.parseFloat(e.target.value)
              onChange({ ...value, rate_alarm_pct: Number.isFinite(parsed) ? parsed : 0 })
            }}
            invalid={pctInvalid}
            aria-label="Rate alarm percentage threshold"
            className="w-20"
          />
          <span>% of findings within</span>
          <Input
            id="auto-dismiss-rate-window"
            type="number"
            min={5}
            max={10080}
            step={1}
            value={value.rate_alarm_window_minutes}
            onChange={(e) => {
              const parsed = Number.parseInt(e.target.value, 10)
              onChange({
                ...value,
                rate_alarm_window_minutes: Number.isFinite(parsed) ? parsed : 0,
              })
            }}
            invalid={windowInvalid}
            aria-label="Rate alarm window in minutes"
            className="w-24"
          />
          <span>minutes</span>
        </div>

        {(pctInvalid || windowInvalid) && (
          <p className="mt-2 text-xs text-[var(--color-severity-critical)]">
            {pctInvalid && "Percentage must be between 1 and 100. "}
            {windowInvalid && "Window must be between 5 and 10080 minutes."}
          </p>
        )}
      </div>
    </div>
  )
}
