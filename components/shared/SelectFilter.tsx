
import type { ReactNode } from "react"

interface SelectFilterProps {
  value: string
  onChange: (v: string) => void
  children: ReactNode
}

export function SelectFilter({ value, onChange, children }: SelectFilterProps) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-sm text-[var(--color-text-primary)]"
    >
      {children}
    </select>
  )
}
