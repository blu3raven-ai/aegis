
export function FindingsEmptyState({
  message = "No findings match the current filters.",
  onClearFilters,
}: {
  message?: string
  /** If provided, renders a "Clear filters" button below the message */
  onClearFilters?: () => void
}) {
  return (
    <div className="flex min-h-[280px] flex-col items-center justify-center gap-2 px-8 text-center">
      <svg
        className="mb-1 h-7 w-7 text-[var(--color-text-tertiary)]"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
      <p className="text-[13px] font-medium text-[var(--color-text-primary)]">{message}</p>
      {onClearFilters && (
        <button
          type="button"
          onClick={onClearFilters}
          className="mt-1 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:border-[var(--color-border-strong)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
        >
          Clear filters
        </button>
      )}
    </div>
  )
}
