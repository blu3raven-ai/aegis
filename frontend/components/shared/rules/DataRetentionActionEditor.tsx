"use client"

/**
 * Editor for the data-retention action portion of a rule. Lets the user
 * pick between archiving (recoverable) and deleting (permanent) scan
 * results once they age past a threshold.
 *
 * Like the SLA and scanner-coverage editors, this editor is permissive:
 * it surfaces inline hints for invalid values but the parent modal owns
 * the final go/no-go validation before submit. There are no destinations
 * here — data retention is an internal lifecycle action with no
 * notification channels.
 */

import type {
  ArchiveAction,
  DataRetentionAction,
  DeleteAction,
} from "@/lib/client/rules-api"

const inputClass =
  "w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-accent)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)] aria-[invalid=true]:border-[var(--color-severity-critical)] aria-[invalid=true]:focus:border-[var(--color-severity-critical)] aria-[invalid=true]:focus:ring-[var(--color-severity-critical)]"

const ARCHIVE_MIN_DAYS = 30
const DELETE_MIN_DAYS = 90
const MAX_DAYS = 3650

export const ARCHIVE_DEFAULT: ArchiveAction = { type: "archive", after_days: 365 }
const DELETE_DEFAULT: DeleteAction = { type: "delete", after_days: 365 }

interface DataRetentionActionEditorProps {
  value: DataRetentionAction
  onChange: (next: DataRetentionAction) => void
}

export function DataRetentionActionEditor({
  value,
  onChange,
}: DataRetentionActionEditorProps) {
  function switchType(next: "archive" | "delete") {
    if (next === value.type) return
    // Reset to the new type's sensible default. If the current value
    // would violate the new floor (e.g. switching archive→delete with
    // 60 days, below the 90-day delete floor), fall back to the
    // default rather than silently keeping an invalid value.
    if (next === "archive") {
      const keep = value.after_days >= ARCHIVE_MIN_DAYS && value.after_days <= MAX_DAYS
      onChange({ type: "archive", after_days: keep ? value.after_days : ARCHIVE_DEFAULT.after_days })
    } else {
      const keep = value.after_days >= DELETE_MIN_DAYS && value.after_days <= MAX_DAYS
      onChange({ type: "delete", after_days: keep ? value.after_days : DELETE_DEFAULT.after_days })
    }
  }

  const minDays = value.type === "delete" ? DELETE_MIN_DAYS : ARCHIVE_MIN_DAYS
  const daysInvalid = !(
    Number.isInteger(value.after_days) &&
    value.after_days >= minDays &&
    value.after_days <= MAX_DAYS
  )

  return (
    <div className="space-y-5">
      <div
        role="radiogroup"
        aria-label="Data retention action type"
        className="grid grid-cols-1 gap-2 sm:grid-cols-2"
      >
        <label className="cursor-pointer rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 has-[input:checked]:border-[var(--color-accent)] has-[input:checked]:bg-[var(--color-accent)]/5">
          <input
            type="radio"
            name="action-type"
            checked={value.type === "archive"}
            onChange={() => switchType("archive")}
            className="sr-only"
          />
          <div className="text-sm font-semibold text-[var(--color-text-primary)]">
            Archive (recommended)
          </div>
          <div className="text-xs text-[var(--color-text-secondary)]">
            Hide from active views but keep the data retrievable.
          </div>
        </label>
        <label className="cursor-pointer rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 has-[input:checked]:border-[var(--color-accent)] has-[input:checked]:bg-[var(--color-accent)]/5">
          <input
            type="radio"
            name="action-type"
            checked={value.type === "delete"}
            onChange={() => switchType("delete")}
            className="sr-only"
          />
          <div className="text-sm font-semibold text-[var(--color-text-primary)]">
            Delete (irreversible)
          </div>
          <div className="text-xs text-[var(--color-text-secondary)]">
            Permanently remove scan history. Findings remain.
          </div>
        </label>
      </div>

      {value.type === "delete" && (
        <div
          role="alert"
          className="rounded-lg border border-[var(--color-severity-critical)] bg-[var(--color-severity-critical)]/10 px-3 py-2 text-xs text-[var(--color-severity-critical)]"
        >
          <span className="font-semibold">Warning:</span> deleting scan results is
          permanent. Findings remain visible but their scan history is lost. Use
          Archive unless you have a compliance reason to delete.
        </div>
      )}

      <div>
        <label
          htmlFor="retention-after-days"
          className="mb-1 block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"
        >
          {value.type === "delete" ? "Delete after" : "Archive after"}
        </label>
        <div className="flex items-center gap-2">
          <input
            id="retention-after-days"
            type="number"
            min={value.type === "delete" ? DELETE_MIN_DAYS : ARCHIVE_MIN_DAYS}
            max={MAX_DAYS}
            step={1}
            value={value.after_days}
            onChange={(e) =>
              onChange({
                ...value,
                after_days: Number.parseInt(e.target.value, 10) || 0,
              })
            }
            aria-invalid={daysInvalid}
            className={`${inputClass} w-28`}
          />
          <span className="text-sm text-[var(--color-text-secondary)]">
            days after the scan finished
          </span>
        </div>
        <p className="mt-1 text-xs text-[var(--color-text-tertiary)]">
          Must be at least {minDays} days (max {MAX_DAYS}).
        </p>
        {daysInvalid && (
          <p className="mt-1 text-xs text-[var(--color-severity-critical)]">
            Enter a whole number between {minDays} and {MAX_DAYS} days.
          </p>
        )}
      </div>
    </div>
  )
}
