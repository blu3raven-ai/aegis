import { Button } from "@/components/ui/Button"

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
      <div className="flex items-center gap-1 text-xs text-[var(--color-text-secondary)]">
        <Button
          variant="ghost"
          size="xs"
          iconOnly
          disabled={isFirst}
          onClick={() => onPageChange(page - 1)}
          aria-label="Previous page"
        >
          ‹
        </Button>
        <span className="tabular-nums px-1">{page} / {totalPages}</span>
        <Button
          variant="ghost"
          size="xs"
          iconOnly
          disabled={isLast}
          onClick={() => onPageChange(page + 1)}
          aria-label="Next page"
        >
          {isLast ? "—" : "›"}
        </Button>
      </div>
    </div>
  )
}
