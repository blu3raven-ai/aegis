import { Database } from "lucide-react"

interface EmptySourcesStateProps {
  filtered?: boolean
}

export function EmptySourcesState({ filtered = false }: EmptySourcesStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-20 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface-raised)]">
        <Database className="h-7 w-7 text-[var(--color-text-secondary)]" aria-hidden />
      </div>
      <div>
        <p className="text-sm font-semibold text-[var(--color-text-primary)]">
          {filtered ? "No sources match your filters" : "No sources connected"}
        </p>
        <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
          {filtered
            ? "Try clearing the search or adjusting the type filter."
            : "Connect a code repository, container registry, or cloud account to start scanning."}
        </p>
      </div>
    </div>
  )
}
