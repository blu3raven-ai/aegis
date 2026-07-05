
import type { ReactNode } from "react"
import { Select } from "@/components/ui/Select"

interface SelectFilterProps {
  value: string
  onChange: (v: string) => void
  children: ReactNode
}

export function SelectFilter({ value, onChange, children }: SelectFilterProps) {
  return (
    <Select
      size="sm"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-auto"
    >
      {children}
    </Select>
  )
}
