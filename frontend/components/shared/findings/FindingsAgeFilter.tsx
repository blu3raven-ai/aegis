"use client"

export type AgePresetKey = "any" | "24h" | "7d" | "30d"

export const AGE_OPTIONS: { value: AgePresetKey; label: string }[] = [
  { value: "any", label: "Any" },
  { value: "24h", label: "Last 24h" },
  { value: "7d",  label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
]

const PRESET_HOURS: Record<Exclude<AgePresetKey, "any">, number> = {
  "24h": 24,
  "7d": 24 * 7,
  "30d": 24 * 30,
}

export function presetToFirstSeenAfter(preset: AgePresetKey): string | null {
  if (preset === "any") return null
  const hours = PRESET_HOURS[preset]
  return new Date(Date.now() - hours * 3600 * 1000).toISOString()
}

export interface FindingsAgeFilterProps {
  value: AgePresetKey
  onChange: (next: AgePresetKey) => void
}

export function FindingsAgeFilter({ value, onChange }: FindingsAgeFilterProps) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as AgePresetKey)}
      aria-label="Filter by age"
      className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1 text-xs text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)]"
    >
      {AGE_OPTIONS.map((opt) => (
        <option key={opt.value} value={opt.value}>Age: {opt.label}</option>
      ))}
    </select>
  )
}
