import { Button } from "@/components/ui/Button"

function ChevronLeftIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="h-3.5 w-3.5" aria-hidden="true">
      <path d="m15 18-6-6 6-6" />
    </svg>
  )
}

function ChevronRightIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="h-3.5 w-3.5" aria-hidden="true">
      <path d="m9 18 6-6-6-6" />
    </svg>
  )
}

export function PaginatedTableFooter({
  totalCount,
  page,
  perPage: _perPage,
  totalPages,
  onPageChange,
  onPerPageChange: _onPerPageChange,
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
  const isFirst = page <= 1
  const isLast = page >= totalPages

  return (
    <div className="flex items-center justify-between border-t border-[var(--color-border)] px-4 py-2.5">
      <span className="text-xs text-[var(--color-text-secondary)]">
        {totalCount} {label}
      </span>
      <nav className="flex items-center gap-1 text-xs text-[var(--color-text-secondary)]" aria-label="Pagination">
        {/* Chevrons must go through leadingIcon: an iconOnly Button drops its
            children, so a glyph passed as a child renders as an empty button. */}
        <Button
          variant="secondary"
          size="xs"
          iconOnly
          disabled={isFirst}
          onClick={() => onPageChange(page - 1)}
          aria-label="Previous page"
          leadingIcon={<ChevronLeftIcon />}
        />
        <span className="tabular-nums px-1">{page} / {totalPages}</span>
        <Button
          variant="secondary"
          size="xs"
          iconOnly
          disabled={isLast}
          onClick={() => onPageChange(page + 1)}
          aria-label="Next page"
          leadingIcon={<ChevronRightIcon />}
        />
      </nav>
    </div>
  )
}
