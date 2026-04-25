interface PageHeaderProps {
  icon: React.ReactNode
  title: string
  /** Short description shown below the title */
  description?: string
  /** @deprecated Use description instead */
  org?: string
  controls?: React.ReactNode
}

export function PageHeader({ icon, title, description, org, controls }: PageHeaderProps) {
  const subtitle = description || org
  return (
    <header className="sticky top-0 z-20 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 py-4">
      <div className="mx-auto flex max-w-7xl items-center gap-4">
        <div className="flex items-center gap-3 min-w-0">
          {icon}
          <div className="min-w-0">
            <h1 className="font-semibold text-[var(--color-text-primary)]">{title}</h1>
            {subtitle && <p className="text-xs text-[var(--color-text-secondary)] truncate">{subtitle}</p>}
          </div>
        </div>
        <div className="ml-auto flex shrink-0 items-center gap-3">
          {controls}
        </div>
      </div>
    </header>
  )
}
