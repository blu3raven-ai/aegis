"use client"

import { FilterChip } from "@/components/ui/FilterChip"
import { FormField } from "@/components/ui/FormField"
import { Select } from "@/components/ui/Select"

// Event filter builder — event type multi-select + min severity picker

// Must mirror the router's SUBSCRIBED_EVENT_TYPES — only these are delivered.
// Offering an event the router drops (chain.*, scan.*) would filter a
// destination down to events it can never receive.
const KNOWN_EVENT_TYPES = [
  "finding.created",
  "finding.severity_changed",
  "intel.exploit_availability_changed",
  "intel.anomaly_detected",
] as const

const SEVERITY_OPTIONS = [
  { value: "", label: "All severities" },
  { value: "low", label: "Low and above" },
  { value: "medium", label: "Medium and above" },
  { value: "high", label: "High and above" },
  { value: "critical", label: "Critical only" },
]

const SEVERITY_COLORS: Record<string, string> = {
  low: "text-[var(--color-severity-low-text)]",
  medium: "text-[var(--color-severity-medium-text)]",
  high: "text-[var(--color-severity-high-text)]",
  critical: "text-[var(--color-severity-critical-text)]",
}

export interface EventFilter {
  event_types?: string[]
  min_severity?: string
}

interface EventFilterBuilderProps {
  value: EventFilter
  onChange: (v: EventFilter) => void
}

export function EventFilterBuilder({ value, onChange }: EventFilterBuilderProps) {
  const selectedTypes = value.event_types ?? []

  function toggleType(et: string) {
    const next = selectedTypes.includes(et)
      ? selectedTypes.filter((t) => t !== et)
      : [...selectedTypes, et]
    onChange({ ...value, event_types: next.length > 0 ? next : undefined })
  }

  function setSeverity(sev: string) {
    onChange({ ...value, min_severity: sev || undefined })
  }

  const allSelected = selectedTypes.length === 0

  return (
    <div className="space-y-3">
      {/* Event types */}
      <div>
        <label className="block text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)] mb-2">
          Event types
        </label>
        <div className="flex flex-wrap gap-1.5">
          <FilterChip
            label="All events"
            active={allSelected}
            onClick={() => onChange({ ...value, event_types: undefined })}
          />
          {KNOWN_EVENT_TYPES.map((et) => (
            <FilterChip
              key={et}
              label={et}
              active={selectedTypes.includes(et)}
              onClick={() => toggleType(et)}
            />
          ))}
        </div>
      </div>

      {/* Min severity */}
      <FormField label="Minimum severity" htmlFor="event-filter-severity">
        <Select
          id="event-filter-severity"
          value={value.min_severity ?? ""}
          onChange={(e) => setSeverity(e.target.value)}
          className="max-w-xs"
        >
          {SEVERITY_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </Select>
        {value.min_severity && (
          <p className={`mt-1 text-[11px] font-medium ${SEVERITY_COLORS[value.min_severity] ?? ""}`}>
            Filtering: {value.min_severity} and above
          </p>
        )}
      </FormField>
    </div>
  )
}
