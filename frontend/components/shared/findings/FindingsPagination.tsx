"use client"

export interface FindingsPaginationProps {
  page: number
  pageSize: number
  total: number
  onChange: (page: number) => void
}

const WINDOW = 3

function visiblePages(page: number, totalPages: number): number[] {
  const start = Math.max(1, page - WINDOW)
  const end = Math.min(totalPages, page + WINDOW)
  const out: number[] = []
  for (let i = start; i <= end; i++) out.push(i)
  return out
}

export function FindingsPagination({ page, pageSize, total, onChange }: FindingsPaginationProps) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const startIdx = total === 0 ? 0 : (page - 1) * pageSize + 1
  const endIdx = Math.min(page * pageSize, total)
  const pages = visiblePages(page, totalPages)

  return (
    <div className="flex items-center justify-between border-t border-[var(--color-border)] px-4 py-2.5 text-xs text-[var(--color-text-secondary)]">
      <span>Showing {startIdx}-{endIdx} of {total} findings</span>
      <nav className="flex items-center gap-1" aria-label="Pagination">
        <button
          type="button"
          disabled={page <= 1}
          onClick={() => onChange(page - 1)}
          aria-label="Previous page"
          className="rounded border border-[var(--color-border)] px-2 py-0.5 hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] disabled:opacity-50 disabled:cursor-not-allowed"
        >◀</button>
        {pages.map((p) => (
          <button
            key={p}
            type="button"
            onClick={() => onChange(p)}
            aria-current={p === page ? "page" : undefined}
            className={`rounded px-2 py-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] ${
              p === page
                ? "bg-[var(--color-accent)] text-[var(--color-accent-on)] font-semibold"
                : "border border-[var(--color-border)] hover:text-[var(--color-text-primary)]"
            }`}
          >{p}</button>
        ))}
        <button
          type="button"
          disabled={page >= totalPages}
          onClick={() => onChange(page + 1)}
          aria-label="Next page"
          className="rounded border border-[var(--color-border)] px-2 py-0.5 hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] disabled:opacity-50 disabled:cursor-not-allowed"
        >▶</button>
      </nav>
    </div>
  )
}
