/**
 * Empty state shown when no repos are found — either not yet scanned or
 * filtered out by the current search/filter criteria.
 */

interface EmptyReposStateProps {
  filtered?: boolean
}

export function EmptyReposState({ filtered = false }: EmptyReposStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-20 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-[var(--color-surface-raised)] border border-[var(--color-border)]">
        <svg
          className="h-7 w-7 text-[var(--color-text-secondary)]"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M14.25 9.75 16.5 12l-2.25 2.25m-4.5 0L7.5 12l2.25-2.25M6 20.25h12A2.25 2.25 0 0 0 20.25 18V6A2.25 2.25 0 0 0 18 3.75H6A2.25 2.25 0 0 0 3.75 6v12A2.25 2.25 0 0 0 6 20.25Z" />
        </svg>
      </div>
      <div>
        <p className="text-sm font-semibold text-[var(--color-text-primary)]">
          {filtered ? "No repos match your filters" : "No repositories yet"}
        </p>
        <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
          {filtered
            ? "Try clearing the search or adjusting the filter."
            : "Repos appear here once Aegis has run its first scan. Connect a source to get started."}
        </p>
      </div>
    </div>
  )
}
