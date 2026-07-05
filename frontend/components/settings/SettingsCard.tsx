import type React from "react"

interface SettingsCardProps {
  /**
   * Optional inner sub-card heading. Renders above the rows in a smaller
   * small-caps style — use it when a section splits its content into multiple
   * thematic groupings.
   */
  heading?: string
  children: React.ReactNode
  /** Optional class extension for the inner surface. */
  className?: string
}

/**
 * Inner sub-card for a settings section. Uses the page background so it
 * visually recedes into a "well" inside the surrounding surface.
 */
export function SettingsCard({ heading, children, className }: SettingsCardProps) {
  return (
    <div className={className}>
      {heading && (
        <p className="mb-2 px-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--color-text-tertiary)]">
          {heading}
        </p>
      )}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)]">
        {children}
      </div>
    </div>
  )
}
