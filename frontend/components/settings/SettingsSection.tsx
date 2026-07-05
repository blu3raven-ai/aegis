import type React from "react"
import { Card } from "@/components/ui/Card"

export interface SettingsSectionProps {
  id: string
  title: string
  subtitle?: string
  headerExtra?: React.ReactNode
  children: React.ReactNode
}

/**
 * Top-level settings section. Renders as the *outer* bordered card — the
 * small-caps title and optional subtitle live inside, with content (one or
 * more SettingsCard inner sub-cards) stacked underneath.
 */
export function SettingsSection({
  id,
  title,
  subtitle,
  headerExtra,
  children,
}: SettingsSectionProps) {
  return (
    <Card
      as="section"
      padding="none"
      id={id}
      className="scroll-mt-4 rounded-xl p-4"
    >
      <header className="mb-3 flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h2 className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]">
            {title}
          </h2>
          {subtitle && (
            <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
              {subtitle}
            </p>
          )}
        </div>
        {headerExtra}
      </header>
      <div className="space-y-3">{children}</div>
    </Card>
  )
}
