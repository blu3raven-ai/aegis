import { Button } from "@/components/ui/Button"

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
      <p className="text-sm font-medium text-[var(--color-text-primary)]">{message}</p>
      {onClearFilters && (
        <Button
          variant="secondary"
          size="sm"
          onClick={onClearFilters}
          className="mt-1"
        >
          Clear filters
        </Button>
      )}
    </div>
  )
}
