import { FilterChip } from "@/components/ui/FilterChip"

interface ToggleChipProps {
  label: string
  active: boolean
  onClick: () => void
  activeColor?: "accent" | "emerald"
}

export function ToggleChip({ label, active, onClick, activeColor = "accent" }: ToggleChipProps) {
  return (
    <FilterChip
      label={label}
      active={active}
      onClick={onClick}
      tone={activeColor === "emerald" ? "success" : "accent"}
    />
  )
}
