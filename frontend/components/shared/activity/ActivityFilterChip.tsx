"use client"

import { FilterChip } from "@/components/ui/FilterChip"

export { eventTypeLabel } from "./event-labels"

interface ActivityFilterChipProps {
  label: string
  active: boolean
  onToggle: () => void
}

export function ActivityFilterChip({ label, active, onToggle }: ActivityFilterChipProps) {
  return <FilterChip label={label} active={active} onClick={onToggle} />
}
