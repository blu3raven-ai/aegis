// components/shared/FindingDrawer/DrawerHeader.tsx

import { Button } from "@/components/ui/Button"
import { LinkButton } from "@/components/ui/LinkButton"

function NavButton({
  direction,
  onClick,
  disabled,
}: {
  direction: "prev" | "next"
  onClick: () => void
  disabled: boolean
}) {
  return (
    <Button
      variant="secondary"
      size="sm"
      iconOnly
      onClick={onClick}
      disabled={disabled}
      aria-label={direction === "prev" ? "Previous finding" : "Next finding"}
      title={direction === "prev" ? "Previous finding (K)" : "Next finding (J)"}
      leadingIcon={
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          {direction === "prev" ? <path d="m18 15-6-6-6 6" /> : <path d="m6 9 6 6 6-6" />}
        </svg>
      }
    />
  )
}

export function DrawerHeader({
  eyebrow,
  eyebrowDotColor,
  title,
  titleTooltip,
  identifier,
  badges,
  repoUrl,
  onClose,
  onPrev,
  onNext,
  hasPrev,
  hasNext,
  position,
  total,
}: {
  eyebrow: string
  eyebrowDotColor?: string
  title: string
  titleTooltip?: string | null
  identifier?: string
  badges?: React.ReactNode
  repoUrl?: string
  onClose: () => void
  /** Step to the previous/next finding in the queue without closing. */
  onPrev?: () => void
  onNext?: () => void
  hasPrev?: boolean
  hasNext?: boolean
  /** Position of this finding within the queue, for an "N / M" indicator. */
  position?: number
  total?: number
}) {
  return (
    <div className="relative border-b border-[var(--color-border)]">
      {/* Severity accent — a restrained colour wash at the top of the panel so
          the analyst registers how bad it is before reading a word. */}
      {eyebrowDotColor && (
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-0 top-0 h-16"
          style={{
            background: `linear-gradient(180deg, color-mix(in srgb, ${eyebrowDotColor} 14%, transparent), transparent)`,
          }}
        />
      )}
      <div className="relative flex items-start justify-between gap-4 p-5">
      <div className="min-w-0">
        <p className="flex items-center gap-2 font-mono text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
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
          className="mt-2 text-lg font-semibold tracking-tight text-[var(--color-text-primary)]"
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
        {(onPrev || onNext) && (
          <div className="flex items-center gap-1">
            <NavButton direction="prev" onClick={() => onPrev?.()} disabled={!hasPrev} />
            {position != null && total != null && total > 0 && (
              <span
                className="min-w-[3rem] px-1 text-center text-xs tabular-nums text-[var(--color-text-tertiary)]"
                aria-label={`Finding ${position} of ${total}`}
              >
                {position}/{total}
              </span>
            )}
            <NavButton direction="next" onClick={() => onNext?.()} disabled={!hasNext} />
          </div>
        )}
        {repoUrl && (
          <LinkButton href={repoUrl} target="_blank" rel="noopener noreferrer" variant="secondary" size="sm">
            View in repository
            <span className="sr-only"> (opens in new tab)</span>
          </LinkButton>
        )}
        <Button
          variant="secondary"
          size="sm"
          onClick={onClose}
          leadingIcon={
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          }
        >
          Close
        </Button>
      </div>
      </div>
    </div>
  )
}
