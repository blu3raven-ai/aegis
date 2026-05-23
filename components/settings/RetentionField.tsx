"use client"

interface RetentionFieldProps {
  /** 0 = keep forever, 1–90 = days before purge */
  value: number
  onChange: (days: number) => void
}

export function RetentionField({ value, onChange }: RetentionFieldProps) {
  const keepForever = value === 0

  return (
    <div className="space-y-2">
      <div className="flex items-start gap-1.5">
        <svg
          className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-text-tertiary)]"
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          aria-hidden="true"
        >
          <circle cx="8" cy="8" r="6.5" />
          <path strokeLinecap="round" d="M8 7.5v4M8 5.5h.01" />
        </svg>
        <p className="text-xs leading-relaxed text-[var(--color-text-tertiary)]">
          Applies to raw scan output in object storage only — findings in the database are not affected.
        </p>
      </div>

      <label className="flex items-center gap-2.5 text-xs text-[var(--color-text-primary)]">
        <input
          type="checkbox"
          checked={keepForever}
          onChange={(e) => onChange(e.target.checked ? 0 : 7)}
          className="h-3.5 w-3.5 rounded border-[var(--color-border)] accent-[var(--color-accent)] focus:ring-2 focus:ring-[var(--color-accent)]/30 disabled:cursor-not-allowed"
        />
        Keep forever
      </label>

      {keepForever ? (
        <p className="text-xs text-[var(--color-text-tertiary)]">
          Artifacts accumulate indefinitely — clean up manually as needed.
        </p>
      ) : (
        <div className="mt-3 space-y-1.5">
          <div className="flex items-center gap-2">
            <input
              type="number"
              min={1}
              max={90}
              value={value}
              onChange={(e) => onChange(Math.min(90, Math.max(1, parseInt(e.target.value) || 7)))}
              className="w-24 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
            />
            <span className="text-xs text-[var(--color-text-secondary)]">days</span>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Purged from object storage after this period (1–90).
          </p>
        </div>
      )}
    </div>
  )
}
