"use client"

import type { ComplianceFramework } from "@/lib/client/compliance-api"

interface FrameworkSelectorProps {
  frameworks: ComplianceFramework[]
  selected: string
  onChange: (framework: string) => void
}

export function FrameworkSelector({ frameworks, selected, onChange }: FrameworkSelectorProps) {
  return (
    <div className="flex items-center gap-2">
      <label
        htmlFor="framework-select"
        className="text-[12px] font-medium text-[var(--color-text-secondary)] shrink-0"
      >
        Framework
      </label>
      <select
        id="framework-select"
        value={selected}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 text-[13px] text-[var(--color-text-primary)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)] transition-colors"
      >
        {frameworks.map((fw) => (
          <option key={fw.id} value={fw.id}>
            {fw.label}
          </option>
        ))}
      </select>
    </div>
  )
}
