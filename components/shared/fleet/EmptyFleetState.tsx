export function EmptyFleetState() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-[var(--color-border)] px-8 py-16 text-center">
      <svg
        className="h-10 w-10 text-[var(--color-text-tertiary)]"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth={1.2}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        {/* server/node icon */}
        <path d="M22 12H2M5 12V6a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v6M5 12v6a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-6M8 6h.01M8 18h.01" />
      </svg>
      <p className="text-sm font-medium text-[var(--color-text-primary)]">No runners reporting yet</p>
      <p className="max-w-sm text-xs leading-relaxed text-[var(--color-text-secondary)]">
        Ensure <code className="rounded bg-[var(--color-surface-raised)] px-1 py-px font-mono text-[11px]">REDIS_URL</code> is
        configured on the runner agents and that at least one runner is running.
      </p>
    </div>
  )
}
