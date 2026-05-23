"use client"

interface RetentionFieldProps {
  /** 0 = keep forever, 1–90 = days before purge */
  value: number
  onChange: (days: number) => void
}

export function RetentionField({ value, onChange }: RetentionFieldProps) {
  const keepForever = value === 0

  return (
    <div className="space-y-3">
      <div className="flex items-start gap-2">
        <svg
          className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-text-tertiary)]"
          viewBox="0 0 16 16"
          fill="currentColor"
          aria-hidden="true"
        >
          <path d="M2 2.5A1.5 1.5 0 013.5 1h9A1.5 1.5 0 0114 2.5v1A1.5 1.5 0 0113 5v8.5A1.5 1.5 0 0111.5 15h-7A1.5 1.5 0 013 13.5V5a1.5 1.5 0 01-1-1.414V2.5zM4.5 5v8.5a.5.5 0 00.5.5h6a.5.5 0 00.5-.5V5h-7zM12.5 4h-9A.5.5 0 013 3.5v-1A.5.5 0 013.5 2h9a.5.5 0 01.5.5v1a.5.5 0 01-.5.5z" />
        </svg>
        <p className="text-xs leading-relaxed text-[var(--color-text-tertiary)]">
          Removes raw scan output from object storage only. Vulnerability findings in the database are not affected.
        </p>
      </div>

      <label className="flex items-center gap-2.5 text-sm text-[var(--color-text-primary)]">
        <input
          type="checkbox"
          checked={keepForever}
          onChange={(e) => onChange(e.target.checked ? 0 : 7)}
          className="h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]/30 disabled:cursor-not-allowed"
        />
        Keep forever
      </label>

      {keepForever ? (
        <p className="text-xs text-[var(--color-text-tertiary)]">
          Artifacts accumulate indefinitely and must be cleaned up manually.
        </p>
      ) : (
        <div>
          <input
            type="number"
            min={1}
            max={90}
            value={value}
            onChange={(e) => onChange(Math.min(90, Math.max(1, parseInt(e.target.value) || 7)))}
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
          />
          <p className="mt-1.5 text-xs text-[var(--color-text-secondary)]">
            Artifacts older than this are purged from object storage (1–90 days).
          </p>
        </div>
      )}
    </div>
  )
}
