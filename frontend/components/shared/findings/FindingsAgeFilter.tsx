"use client"

import { Select } from "@/components/ui/Select"

export type AgePresetKey = "any" | "24h" | "7d" | "30d" | "90d"

export const AGE_OPTIONS: { value: AgePresetKey; label: string }[] = [
  { value: "any", label: "Any" },
  { value: "24h", label: "Last 24h" },
  { value: "7d",  label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "90d", label: "Last 90 days" },
]

const PRESET_HOURS: Record<Exclude<AgePresetKey, "any">, number> = {
  "24h": 24,
  "7d": 24 * 7,
  "30d": 24 * 30,
  "90d": 24 * 90,
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
    <Select
      size="sm"
      value={value}
      onChange={(e) => onChange(e.target.value as AgePresetKey)}
      aria-label="Filter by age"
    >
      {AGE_OPTIONS.map((opt) => (
        <option key={opt.value} value={opt.value}>Age: {opt.label}</option>
      ))}
    </Select>
  )
}
