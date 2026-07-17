"use client"

import { CODE_SCANNING_RULESETS, type RulesetGroup } from "@/lib/shared/code-scanning-rulesets"

interface RulesetPickerProps {
  selected: string[]
  onChange: (selected: string[]) => void
  disabled?: boolean
}

const GROUP_LABELS: Record<RulesetGroup, string> = {
  security: "Security",
  languages: "Languages",
  frameworks: "Frameworks",
}

const GROUPS: RulesetGroup[] = ["security"]

function toggle(selected: string[], id: string): string[] {
  return selected.includes(id)
    ? selected.filter((s) => s !== id)
    : [...selected, id]
}

export function RulesetPicker({ selected, onChange, disabled }: RulesetPickerProps) {
  const rulesets = CODE_SCANNING_RULESETS.filter((r) => r.group === "security")
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      {rulesets.map((r) => {
        const active = selected.includes(r.id)
        return (
          <button
            key={r.id}
            type="button"
            disabled={disabled}
            onClick={() => onChange(toggle(selected, r.id))}
            className={`rounded-md border px-4 py-4 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
              active
                ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)]"
                : "border-[var(--color-border)] hover:border-[var(--color-text-secondary)]"
            }`}
          >
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${active ? "bg-[var(--color-accent)]" : "bg-[var(--color-text-secondary)]"}`} />
              <span className={`text-sm font-semibold ${active ? "text-[var(--color-accent)]" : "text-[var(--color-text-primary)]"}`}>
                {r.name}
              </span>
            </div>
            {r.description && (
              <p className="mt-2 text-xs leading-relaxed text-[var(--color-text-secondary)]">{r.description}</p>
            )}
          </button>
        )
      })}
    </div>
  )
}
