"use client"

import { useMemo } from "react"

import { CommandBar, type AttributeDef } from "@/components/shared/command-bar"
import { SegmentedControl } from "@/components/ui/SegmentedControl"

export type DateWindow = "7d" | "30d" | "90d" | "all"

export interface AuditFilters {
  dateWindow: DateWindow
  /** Free-text query matched across action, actor, and resource. */
  q: string
  /** Exact action filter. */
  action: string
  /** Exact resource-type filter. */
  resourceType: string
}

const DATE_CHIPS: { label: string; value: DateWindow }[] = [
  { label: "7d", value: "7d" },
  { label: "30d", value: "30d" },
  { label: "90d", value: "90d" },
  { label: "All time", value: "all" },
]

interface AuditCommandBarProps {
  dateWindow: DateWindow
  onDateWindowChange: (value: DateWindow) => void
  search: string
  onSearchChange: (value: string) => void
  onSearchSubmit?: () => void
  action: string
  onActionChange: (value: string) => void
  resourceType: string
  onResourceTypeChange: (value: string) => void
  /** Distinct values from the whole log, for the filter pickers. */
  actionOptions: string[]
  resourceTypeOptions: string[]
}

/**
 * Audit filter bar built on the shared CommandBar — same search-and-filter
 * surface as /findings and /sources. Free text searches action/actor/resource;
 * the action and resource pickers narrow by exact value. The date range stays a
 * separate always-visible scope control.
 */
export function AuditCommandBar({
  dateWindow,
  onDateWindowChange,
  search,
  onSearchChange,
  onSearchSubmit,
  action,
  onActionChange,
  resourceType,
  onResourceTypeChange,
  actionOptions,
  resourceTypeOptions,
}: AuditCommandBarProps) {
  const attributes = useMemo<AttributeDef[]>(
    () => [
      {
        key: "action",
        label: "action",
        group: "Audit",
        description: "Event type",
        type: "enum",
        options: actionOptions.map((a) => ({ value: a, label: a })),
      },
      {
        key: "resource",
        label: "resource",
        group: "Audit",
        description: "Affected resource type",
        type: "enum",
        options: resourceTypeOptions.map((r) => ({ value: r, label: r })),
      },
    ],
    [actionOptions, resourceTypeOptions],
  )

  const values = useMemo<Record<string, string | null>>(
    () => ({ action: action || null, resource: resourceType || null }),
    [action, resourceType],
  )

  const handleChange = (key: string, value: string | null) => {
    if (key === "action") onActionChange(value ?? "")
    else if (key === "resource") onResourceTypeChange(value ?? "")
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <SegmentedControl<DateWindow>
        options={DATE_CHIPS.map((c) => ({ id: c.value, label: c.label }))}
        value={dateWindow}
        onChange={onDateWindowChange}
        ariaLabel="Date range"
      />
      <div className="min-w-[240px] flex-1">
        <CommandBar
          attributes={attributes}
          values={values}
          onChange={handleChange}
          searchInput={search}
          onSearchInputChange={onSearchChange}
          onSearchSubmit={onSearchSubmit}
          searchPlaceholder="Search or filter audit events…"
        />
      </div>
    </div>
  )
}
