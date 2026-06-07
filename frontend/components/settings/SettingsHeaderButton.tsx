import type { ReactNode } from "react"

interface SettingsHeaderButtonProps {
  onClick: () => void
  icon: ReactNode
  children: ReactNode
}

/**
 * Primary action button that sits next to a SettingsSection's heading via the
 * section's `headerExtra` slot. Keeps the action visually paired with the
 * section title instead of dropping it onto a separate row above the content.
 */
export function SettingsHeaderButton({
  onClick,
  icon,
  children,
}: SettingsHeaderButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1.5 rounded-md bg-[var(--color-accent)] px-3 py-1.5 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-bg)]"
    >
      <span aria-hidden="true" className="h-3.5 w-3.5">
        {icon}
      </span>
      {children}
    </button>
  )
}
