export function EmptyActivityState() {
  return (
    <div
      className="flex flex-col items-center gap-3 py-16 text-center"
      data-testid="empty-activity-state"
    >
      <svg
        className="h-10 w-10 text-[var(--color-text-secondary)] opacity-40"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
      </svg>
      <p className="text-sm font-medium text-[var(--color-text-primary)]">
        No activity yet
      </p>
      <p className="max-w-xs text-xs text-[var(--color-text-secondary)]">
        Nothing has happened yet. Check back later once scans have run or findings have been triaged.
      </p>
    </div>
  )
}
