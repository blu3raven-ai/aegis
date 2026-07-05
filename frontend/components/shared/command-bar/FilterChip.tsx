"use client"

export interface FilterChipProps {
  field: string
  /** Display value; null renders the placeholder state ("pick…"). */
  value: string | null
  /** Use "danger" for binary risk signals (e.g., KEV). */
  variant?: "default" | "danger"
  /** Picker is currently open for this chip — rotates chevron, brightens border. */
  isActive?: boolean
  onClickBody: () => void
  onRemove: () => void
}

const VARIANT_CLASS = {
  default:
    "border-[var(--color-accent-border)] bg-[var(--color-accent-subtle)] hover:border-[var(--color-accent)]",
  danger:
    "border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] hover:border-[var(--color-severity-critical)]",
} as const

const VALUE_CLASS = {
  default: "text-[var(--color-text-primary)]",
  danger: "text-[var(--color-severity-critical-text)]",
} as const

const FIELD_CLASS = {
  default: "text-[var(--color-text-secondary)]",
  danger: "text-[var(--color-severity-critical-text)] opacity-80",
} as const

const X_BORDER_CLASS = {
  default: "border-[var(--color-accent-border)]",
  danger: "border-[var(--color-severity-critical-border)]",
} as const

export function FilterChip({
  field,
  value,
  variant = "default",
  isActive = false,
  onClickBody,
  onRemove,
}: FilterChipProps) {
  const isPlaceholder = value === null
  const ringClass = isActive ? "ring-2 ring-[var(--color-accent)]/40 border-[var(--color-accent)]" : ""

  return (
    <span
      className={`inline-flex h-7 items-stretch overflow-hidden rounded-md border transition-colors ${VARIANT_CLASS[variant]} ${ringClass}`}
    >
      <button
        type="button"
        onClick={onClickBody}
        aria-expanded={isActive}
        aria-label={isPlaceholder ? `Pick ${field} value` : `Edit ${field}: ${value}`}
        className="inline-flex items-center gap-1 px-2.5 text-xs hover:bg-[var(--color-accent)]/5 focus-visible:outline-none focus-visible:bg-[var(--color-accent)]/5"
      >
        <span className={`font-medium ${FIELD_CLASS[variant]}`}>{field}</span>
        <span aria-hidden className="text-[var(--color-text-tertiary)]">
          :
        </span>
        {isPlaceholder ? (
          <span className="italic text-[var(--color-text-tertiary)]">pick…</span>
        ) : (
          <span className={`font-semibold ${VALUE_CLASS[variant]}`}>{value}</span>
        )}
        <svg
          aria-hidden
          className={`ml-0.5 h-2.5 w-2.5 text-[var(--color-text-tertiary)] transition-transform ${isActive ? "rotate-180" : ""}`}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.4"
          strokeLinecap="round"
        >
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>
      <button
        type="button"
        onClick={onRemove}
        aria-label={`Remove ${field} filter`}
        className={`inline-grid w-5 place-items-center border-l text-[var(--color-text-tertiary)] hover:bg-[var(--color-accent)]/10 hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:bg-[var(--color-accent)]/10 ${X_BORDER_CLASS[variant]}`}
      >
        <svg
          aria-hidden
          className="h-2.5 w-2.5"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.4"
          strokeLinecap="round"
        >
          <path d="M18 6 6 18M6 6l12 12" />
        </svg>
      </button>
    </span>
  )
}
