import type React from "react"

interface SettingsRowProps {
  label: string
  description?: string
  /** Right-side content. Rendered inline next to the label by default. */
  children: React.ReactNode
  /**
   * `inline` (default): label+description on the left, children on the right
   * — for short controls (toggle, value+Edit button, compact select).
   *
   * `stack`: label+description above, children below — for full-width form
   * inputs that need their own row underneath the label.
   */
  layout?: "inline" | "stack"
}

/**
 * One row inside a SettingsCard. Rows divide themselves with bottom borders
 * so consumers don't have to wire `divide-y` on the card.
 */
export function SettingsRow({
  label,
  description,
  children,
  layout = "inline",
}: SettingsRowProps) {
  const labelBlock = (
    <div className="min-w-0">
      <p className="text-sm font-medium text-[var(--color-text-primary)]">{label}</p>
      {description && (
        <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
          {description}
        </p>
      )}
    </div>
  )

  if (layout === "stack") {
    return (
      <div className="border-b border-[var(--color-border)] px-4 py-4 last:border-b-0">
        {labelBlock}
        <div className="mt-3">{children}</div>
      </div>
    )
  }

  return (
    <div className="flex items-center justify-between gap-4 border-b border-[var(--color-border)] px-4 py-4 last:border-b-0">
      {labelBlock}
      <div className="flex shrink-0 items-center gap-3">{children}</div>
    </div>
  )
}
