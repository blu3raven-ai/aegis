// Shown when no destinations exist

import { Button } from "@/components/ui/Button"

export function EmptyDestinationsState({ onAdd }: { onAdd: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 rounded-md border border-dashed border-[var(--color-border-strong)] bg-[var(--color-surface)] py-16">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[var(--color-accent)]/10">
        <svg
          className="h-6 w-6 text-[var(--color-accent)]"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M14.857 17.082a23.848 23.848 0 0 0 5.454-1.31A8.967 8.967 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.967 8.967 0 0 1-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 0 1-5.714 0m5.714 0a3 3 0 1 1-5.714 0" />
        </svg>
      </div>
      <div className="text-center">
        <p className="text-sm font-semibold text-[var(--color-text-primary)]">
          No notification destinations
        </p>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Route critical events to Slack, a webhook, or email.
        </p>
      </div>
      <Button variant="primary" size="md" onClick={onAdd}>
        Add your first destination
      </Button>
    </div>
  )
}
