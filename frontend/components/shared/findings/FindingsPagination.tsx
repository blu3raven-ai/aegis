"use client"

import { Button } from "@/components/ui/Button"

export interface FindingsPaginationProps {
  page: number
  pageSize: number
  total: number
  onChange: (page: number) => void
}

const WINDOW = 3

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
        <Button
          variant="secondary"
          size="xs"
          iconOnly
          disabled={page <= 1}
          onClick={() => onChange(page - 1)}
          aria-label="Previous page"
          leadingIcon={<ChevronLeftIcon />}
        />
        {pages.map((p) => (
          <Button
            key={p}
            variant={p === page ? "primary" : "secondary"}
            size="xs"
            onClick={() => onChange(p)}
            aria-current={p === page ? "page" : undefined}
          >
            {p}
          </Button>
        ))}
        <Button
          variant="secondary"
          size="xs"
          iconOnly
          disabled={page >= totalPages}
          onClick={() => onChange(page + 1)}
          aria-label="Next page"
          leadingIcon={<ChevronRightIcon />}
        />
      </nav>
    </div>
  )
}
