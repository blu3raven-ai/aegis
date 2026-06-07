import type React from "react"

export interface SettingsFieldRowProps {
  label: string
  description?: string
  children: React.ReactNode
}

export function SettingsFieldRow({ label, description, children }: SettingsFieldRowProps) {
  return (
    <div className="grid grid-cols-[180px_1fr] items-center gap-6 border-t border-[var(--color-border)] py-3.5 first:border-t-0 first:pt-0">
      <div>
        <div className="text-sm font-medium text-[var(--color-text-primary)]">{label}</div>
        {description && (
          <div className="mt-0.5 text-xs text-[var(--color-text-tertiary)]">{description}</div>
        )}
      </div>
      <div className="min-w-0">{children}</div>
    </div>
  )
}
