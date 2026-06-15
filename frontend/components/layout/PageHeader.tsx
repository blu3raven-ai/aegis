interface PageHeaderProps {
  icon: React.ReactNode
  title: string
  /** Short description shown below the title */
  description?: string
  /** Inline pill rendered next to the title — mirrors the mock's pageheader-count. */
  count?: number | null
  /** Optional ReactNode rendered inline next to the title (e.g. a TypeChip). */
  meta?: React.ReactNode
  controls?: React.ReactNode
}

export function PageHeader({ icon, title, description, count, meta, controls }: PageHeaderProps) {
  const showCount = typeof count === "number" && Number.isFinite(count)
  return (
    <header className="border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-4">
      <div className="flex w-full items-center gap-4">
        <div className="flex items-center gap-3 min-w-0">
          {icon}
          <div className="min-w-0">
            <h1 className="flex items-baseline gap-2 text-lg font-semibold tracking-tight text-[var(--color-text-primary)]">
              <span className="truncate">{title}</span>
              {showCount && (
                <span className="shrink-0 rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5 text-xs font-medium tabular-nums text-[var(--color-text-secondary)]">
                  {count.toLocaleString()}
                </span>
              )}
              {meta && <span className="shrink-0">{meta}</span>}
            </h1>
            {description && <p className="text-xs text-[var(--color-text-secondary)] truncate">{description}</p>}
          </div>
        </div>
        <div className="ml-auto flex shrink-0 items-center gap-3">
          {controls}
        </div>
      </div>
    </header>
  )
}
