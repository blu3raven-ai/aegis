"use client"

import type { ComplianceFramework } from "@/lib/client/compliance-api"
import { Select } from "@/components/ui/Select"

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
        className="text-xs font-medium text-[var(--color-text-secondary)] shrink-0"
      >
        Framework
      </label>
      <Select
        size="sm"
        id="framework-select"
        data-testid="framework-selector"
        value={selected}
        onChange={(e) => onChange(e.target.value)}
        className="w-auto"
      >
        {frameworks.map((fw) => (
          <option key={fw.id} value={fw.id}>
            {fw.label}
          </option>
        ))}
      </Select>
    </div>
  )
}
