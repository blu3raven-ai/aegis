"use client"

import { FilterTag } from "@/components/shared/FilterTag"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { Select } from "@/components/ui/Select"

export type DateWindow = "7d" | "30d" | "90d" | "all"

export interface AuditFilters {
  dateWindow: DateWindow
  action: string
  actorId: string
  resourceType: string
}

const DATE_CHIPS: { label: string; value: DateWindow }[] = [
  { label: "7d", value: "7d" },
  { label: "30d", value: "30d" },
  { label: "90d", value: "90d" },
  { label: "All time", value: "all" },
]

interface AuditFilterBarProps {
  filters: AuditFilters
  onChange: (next: Partial<AuditFilters>) => void
  // Unique action values seen in the current data, for the dropdown
  knownActions?: string[]
  knownActors?: { id: string; email?: string }[]
  knownResourceTypes?: string[]
}

export function AuditFilterBar({
  filters,
  onChange,
  knownActions = [],
  knownActors = [],
  knownResourceTypes = [],
}: AuditFilterBarProps) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {/* Date range chips */}
      <SegmentedControl<DateWindow>
        options={DATE_CHIPS.map((c) => ({ id: c.value, label: c.label }))}
        value={filters.dateWindow}
        onChange={(v) => onChange({ dateWindow: v })}
        ariaLabel="Date range"
      />

      {/* Action filter */}
      {knownActions.length > 0 && !filters.action && (
        <SelectChip
          placeholder="Action"
          options={knownActions}
          onSelect={(v) => onChange({ action: v })}
        />
      )}
      {filters.action && (
        <FilterTag
          label={`action: ${filters.action}`}
          onClear={() => onChange({ action: "" })}
          color="accent"
        />
      )}

      {/* Actor filter */}
      {knownActors.length > 0 && !filters.actorId && (
        <SelectChip
          placeholder="Actor"
          options={knownActors.map((a) => a.email ?? a.id)}
          rawValues={knownActors.map((a) => a.id)}
          onSelect={(v) => onChange({ actorId: v })}
        />
      )}
      {filters.actorId && (
        <FilterTag
          label={`actor: ${filters.actorId}`}
          onClear={() => onChange({ actorId: "" })}
          color="emerald"
        />
      )}

      {/* Resource type filter */}
      {knownResourceTypes.length > 0 && !filters.resourceType && (
        <SelectChip
          placeholder="Resource"
          options={knownResourceTypes}
          onSelect={(v) => onChange({ resourceType: v })}
        />
      )}
      {filters.resourceType && (
        <FilterTag
          label={`resource: ${filters.resourceType}`}
          onClear={() => onChange({ resourceType: "" })}
          color="orange"
        />
      )}
    </div>
  )
}

// Inline lightweight dropdown chip — avoids pulling in a heavy Select library
function SelectChip({
  placeholder,
  options,
  rawValues,
  onSelect,
}: {
  placeholder: string
  options: string[]
  rawValues?: string[]
  onSelect: (value: string) => void
}) {
  return (
    <Select
      size="sm"
      className="w-auto cursor-pointer"
      value=""
      onChange={(e) => {
        if (e.target.value) onSelect(e.target.value)
      }}
    >
      <option value="">{placeholder} ▾</option>
      {options.map((opt, i) => (
        <option key={opt} value={rawValues ? rawValues[i] : opt}>
          {opt}
        </option>
      ))}
    </Select>
  )
}
