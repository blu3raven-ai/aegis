"use client"

import { useMemo } from "react"

import { CommandBar, type AttributeDef } from "@/components/shared/command-bar"
import type { SourceType as SourceCategoryUiType } from "@/components/ui/TypeChip"

interface SourcesCommandBarProps {
  search: string
  onSearchChange: (next: string) => void
  typeFilter: SourceCategoryUiType | "all"
  onTypeChange: (next: SourceCategoryUiType | "all") => void
}

// Thin wrapper around the shared CommandBar — mirrors the pattern used by
// /findings and /inbox so the search bar reads consistently across the app.
// Type filter is the only dimension Sources cares about today; add new
// attributes here as the surface grows.
const ATTRIBUTES: AttributeDef[] = [
  {
    key: "type",
    label: "type",
    group: "Source",
    description: "Code · Containers · Cloud",
    type: "enum",
    options: [
      { value: "code", label: "Code" },
      { value: "containers", label: "Containers" },
      { value: "cloud", label: "Cloud" },
    ],
  },
]

export function SourcesCommandBar({
  search,
  onSearchChange,
  typeFilter,
  onTypeChange,
}: SourcesCommandBarProps) {
  const values = useMemo<Record<string, string | null>>(
    () => ({ type: typeFilter === "all" ? null : typeFilter }),
    [typeFilter],
  )

  const handleChange = (key: string, value: string | null) => {
    if (key === "type") {
      onTypeChange((value as SourceCategoryUiType) ?? "all")
    }
  }

  return (
    <CommandBar
      attributes={ATTRIBUTES}
      values={values}
      onChange={handleChange}
      searchInput={search}
      onSearchInputChange={onSearchChange}
      searchPlaceholder="Search sources…"
    />
  )
}
