
const PER_PAGE_OPTIONS = [25, 50, 100]

export function PaginatedTableFooter({
  totalCount,
  page,
  perPage,
  totalPages,
  onPageChange,
  onPerPageChange,
  label = "findings",
}: {
  totalCount: number
  page: number
  perPage: number
  totalPages: number
  onPageChange: (page: number) => void
  onPerPageChange: (perPage: number) => void
  label?: string
}) {
  return (
    <div className="flex items-center justify-between border-t border-[var(--color-border)] px-4 py-3">
      <div className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
        <span>Rows per page:</span>
        {PER_PAGE_OPTIONS.map((n) => (
          <button
            key={n}
            type="button"
            onClick={() => { onPerPageChange(n); onPageChange(1) }}
            className={`rounded px-2 py-1 font-semibold transition-colors ${perPage === n ? "bg-[var(--color-accent)] text-white" : "hover:text-[var(--color-text-primary)]"}`}
          >
            {n}
          </button>
        ))}
      </div>
      <div className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
        <span>{totalCount} {label} · page {page} of {totalPages}</span>
        <button
          type="button"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
          className="rounded border border-[var(--color-border)] px-2 py-1 disabled:opacity-40 hover:bg-[var(--color-surface-raised)]"
        >
          ‹
        </button>
        <button
          type="button"
          disabled={page >= totalPages}
          onClick={() => onPageChange(page + 1)}
          className="rounded border border-[var(--color-border)] px-2 py-1 disabled:opacity-40 hover:bg-[var(--color-surface-raised)]"
        >
          ›
        </button>
      </div>
    </div>
  )
}
