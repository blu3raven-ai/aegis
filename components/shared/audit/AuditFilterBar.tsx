"use client"

import { FilterTag } from "@/components/shared/FilterTag"

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
      <div className="flex items-center gap-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-1">
        {DATE_CHIPS.map((chip) => (
          <button
            key={chip.value}
            type="button"
            onClick={() => onChange({ dateWindow: chip.value })}
            className={`rounded-md px-3 py-1 text-xs font-semibold transition-colors ${
              filters.dateWindow === chip.value
                ? "bg-[var(--color-accent)] text-[var(--color-accent-on)]"
                : "text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]"
            }`}
          >
            {chip.label}
          </button>
        ))}
      </div>

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
    <select
      className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs text-[var(--color-text-secondary)] hover:border-[var(--color-border-strong)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)] cursor-pointer"
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
    </select>
  )
}
