export function EmptyAuditState({ filtered }: { filtered?: boolean }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-8 text-center">
      <svg
        className="h-10 w-10 text-[var(--color-text-tertiary)] mb-4"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.2}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z" />
      </svg>
      <p className="text-sm font-semibold text-[var(--color-text-secondary)]">
        {filtered ? "No audit events match your filters" : "No audit events recorded yet"}
      </p>
      <p className="mt-1 text-sm text-[var(--color-text-tertiary)]">
        {filtered
          ? "Try widening the date range or clearing some filters."
          : "Audit events will appear here once admin actions are performed."}
      </p>
    </div>
  )
}
