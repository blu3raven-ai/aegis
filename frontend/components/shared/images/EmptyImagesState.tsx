/**
 * Empty state shown when no images are found — either not yet scanned or
 * filtered out by the current search/filter criteria.
 *
 * Mirrors EmptyReposState so /repos and /images render at the same height.
 * The page-level "Add source" button covers the connect-a-source affordance,
 * so this state stays compact (icon + message only).
 */

interface EmptyImagesStateProps {
  filtered?: boolean
}

export function EmptyImagesState({ filtered = false }: EmptyImagesStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-20 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)]">
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
          <path d="M3.75 6.75A2.25 2.25 0 0 1 6 4.5h12a2.25 2.25 0 0 1 2.25 2.25v10.5A2.25 2.25 0 0 1 18 19.5H6A2.25 2.25 0 0 1 3.75 17.25V6.75ZM3.75 16.5l4.5-4.5 3 3 3-3 6 6m-6-9a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0Z" />
        </svg>
      </div>
      <div>
        <p className="text-sm font-semibold text-[var(--color-text-primary)]">
          {filtered ? "No images match your filters" : "No container images yet"}
        </p>
        <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
          {filtered
            ? "Try clearing the search or adjusting the filter."
            : "Container images appear here once Aegis scans them. Connect a source to get started."}
        </p>
      </div>
    </div>
  )
}
