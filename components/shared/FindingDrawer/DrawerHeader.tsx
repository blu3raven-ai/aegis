// components/shared/FindingDrawer/DrawerHeader.tsx

export function DrawerHeader({
  eyebrow,
  title,
  titleTooltip,
  identifier,
  badges,
  repoUrl,
  onClose,
}: {
  eyebrow: string
  title: string
  titleTooltip?: string
  identifier?: string
  badges?: React.ReactNode
  repoUrl?: string
  onClose: () => void
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-[var(--color-border)] p-5">
      <div className="min-w-0">
        <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-[var(--color-text-secondary)]">
          {eyebrow}
        </p>
        <h2
          className="mt-2 text-xl font-semibold text-[var(--color-text-primary)]"
          title={titleTooltip}
        >
          {title}
        </h2>
        {identifier && (
          <p className="mt-1 truncate font-[family-name:var(--font-jetbrains-mono)] text-xs text-[var(--color-text-secondary)]">
            {identifier}
          </p>
        )}
        {badges && (
          <div className="mt-3 flex flex-wrap items-center gap-2">{badges}</div>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {repoUrl && (
          <a
            href={repoUrl}
            target="_blank"
            rel="noreferrer"
            className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-accent)] hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
          >
            View in repository
          </a>
        )}
        <button
          type="button"
          onClick={onClose}
          className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
        >
          ✕ Close
        </button>
      </div>
    </div>
  )
}
