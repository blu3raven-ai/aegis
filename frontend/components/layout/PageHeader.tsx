import { PageEyebrow } from "./PageEyebrow"

interface PageHeaderProps {
  /** Retained for source compatibility; the header no longer renders an icon
   *  tile — it leads with a mono section eyebrow instead. */
  icon?: React.ReactNode
  title: string
  /** Short description shown below the title */
  description?: string
  /** Inline pill rendered next to the title. */
  count?: number | null
  /** Optional ReactNode rendered inline next to the title (e.g. a TypeChip). */
  meta?: React.ReactNode
  controls?: React.ReactNode
}

export function PageHeader({ title, description, count, meta, controls }: PageHeaderProps) {
  const showCount = typeof count === "number" && Number.isFinite(count)
  return (
    <header className="sticky top-0 z-20 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-4">
      <div className="flex w-full items-start gap-4">
        <div className="min-w-0">
          <PageEyebrow />
          <h1 className="flex items-baseline gap-2 text-2xl font-semibold tracking-[-0.02em] text-[var(--color-text-primary)]">
            <span className="truncate">{title}</span>
            {showCount && (
              <span className="shrink-0 rounded-full bg-[var(--color-surface-raised)] px-2 py-0.5 font-mono text-2xs font-semibold tabular-nums text-[var(--color-text-secondary)]">
                {count.toLocaleString()}
              </span>
            )}
            {meta && <span className="shrink-0">{meta}</span>}
          </h1>
          {description && <p className="mt-1 text-xs text-[var(--color-text-secondary)] truncate">{description}</p>}
        </div>
        <div className="ml-auto flex shrink-0 items-center gap-3">
          {controls}
        </div>
      </div>
    </header>
  )
}
