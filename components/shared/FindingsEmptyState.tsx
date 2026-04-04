
export function FindingsEmptyState({
  message = "No findings match the current filters.",
}: {
  message?: string
}) {
  return (
    <div className="flex min-h-[300px] items-center justify-center text-sm text-[var(--color-text-secondary)]">
      {message}
    </div>
  )
}
