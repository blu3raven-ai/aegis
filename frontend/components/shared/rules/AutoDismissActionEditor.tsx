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

const inputClass =
  "w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-accent)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)] aria-[invalid=true]:border-[var(--color-severity-critical)] aria-[invalid=true]:focus:border-[var(--color-severity-critical)] aria-[invalid=true]:focus:ring-[var(--color-severity-critical)]"

const textareaClass = `${inputClass} min-h-[72px] resize-y`

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
      <div>
        <label
          htmlFor="auto-dismiss-reason"
          className="mb-1 block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"
        >
          User-facing dismiss reason
        </label>
        <textarea
          id="auto-dismiss-reason"
          value={value.reason}
          onChange={(e) => onChange({ ...value, reason: e.target.value })}
          placeholder="Auto-dismissed: test fixtures excluded"
          aria-invalid={reasonInvalid}
          maxLength={200}
          className={textareaClass}
        />
        <div className="mt-1 flex items-center justify-between">
          <p
            className={`text-xs ${
              reasonInvalid
                ? "text-[var(--color-severity-critical)]"
                : "text-[var(--color-text-tertiary)]"
            }`}
          >
            {reasonInvalid
              ? "Reason must be between 3 and 200 characters."
              : "Shown to anyone reviewing the auto-dismissed finding."}
          </p>
          <span className="text-2xs text-[var(--color-text-tertiary)]">{reasonLen} / 200</span>
        </div>
      </div>

      <div>
        <label
          htmlFor="auto-dismiss-audit-note"
          className="mb-1 block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"
        >
          Audit note <span className="font-normal normal-case tracking-normal text-[var(--color-text-tertiary)]">(internal, optional)</span>
        </label>
        <textarea
          id="auto-dismiss-audit-note"
          value={value.audit_note ?? ""}
          onChange={(e) => onChange({ ...value, audit_note: e.target.value })}
          placeholder="Hides findings from **/test/** trees"
          aria-invalid={auditNoteInvalid}
          maxLength={500}
          className={textareaClass}
        />
        <div className="mt-1 flex items-center justify-between">
          <p
            className={`text-xs ${
              auditNoteInvalid
                ? "text-[var(--color-severity-critical)]"
                : "text-[var(--color-text-tertiary)]"
            }`}
          >
            {auditNoteInvalid
              ? "Audit note must be 500 characters or fewer."
              : "Visible only to admins reviewing rule history."}
          </p>
          <span className="text-2xs text-[var(--color-text-tertiary)]">{auditNoteLen} / 500</span>
        </div>
      </div>

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
          <input
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
            aria-invalid={pctInvalid}
            aria-label="Rate alarm percentage threshold"
            className={`${inputClass} w-20`}
          />
          <span>% of findings within</span>
          <input
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
            aria-invalid={windowInvalid}
            aria-label="Rate alarm window in minutes"
            className={`${inputClass} w-24`}
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
