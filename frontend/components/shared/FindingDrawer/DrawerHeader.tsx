// components/shared/FindingDrawer/DrawerHeader.tsx

export function DrawerHeader({
  eyebrow,
  eyebrowDotColor,
  title,
  titleTooltip,
  identifier,
  badges,
  repoUrl,
  onClose,
}: {
  eyebrow: string
  eyebrowDotColor?: string
  title: string
  titleTooltip?: string | null
  identifier?: string
  badges?: React.ReactNode
  repoUrl?: string
  onClose: () => void
}) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-[var(--color-border)] p-5">
      <div className="min-w-0">
        <p className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
          {eyebrowDotColor && (
            <span
              aria-hidden="true"
              className="inline-block h-2 w-2 shrink-0 rounded-full"
              style={{ background: eyebrowDotColor }}
            />
          )}
          {eyebrow}
        </p>
        <h2
          className="mt-2 text-xl font-semibold text-[var(--color-text-primary)]"
          title={titleTooltip ?? undefined}
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
            className="rounded-lg border border-[var(--color-border)] px-3 py-2 text-xs font-semibold text-[var(--color-accent)] hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
          >
            View in repository
            <span className="sr-only"> (opens in new tab)</span>
          </a>
        )}
        <button
          type="button"
          onClick={onClose}
          className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-2 text-xs font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
        >
          <svg
            width="12"
            height="12"
            viewBox="0 0 12 12"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            aria-hidden="true"
          >
            <path d="M1 1l10 10M11 1L1 11" />
          </svg>
          <span>Close</span>
        </button>
      </div>
    </div>
  )
}
