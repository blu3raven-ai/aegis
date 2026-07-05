"use client"

// Event filter builder — event type multi-select + min severity picker

const KNOWN_EVENT_TYPES = [
  "chain.created",
  "chain.updated",
  "finding.created",
  "finding.state_changed",
  "intel.exploit_availability_changed",
  "intel.anomaly_detected",
  "scan.completed",
  "scan.failed",
] as const

const SEVERITY_OPTIONS = [
  { value: "", label: "All severities" },
  { value: "low", label: "Low and above" },
  { value: "medium", label: "Medium and above" },
  { value: "high", label: "High and above" },
  { value: "critical", label: "Critical only" },
]

const SEVERITY_COLORS: Record<string, string> = {
  low: "text-[var(--color-severity-low)]",
  medium: "text-[var(--color-severity-medium)]",
  high: "text-[var(--color-severity-high)]",
  critical: "text-[var(--color-severity-critical)]",
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
        <label className="block text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)] mb-2">
          Event types
        </label>
        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => onChange({ ...value, event_types: undefined })}
            className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
              allSelected
                ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                : "border-[var(--color-border)] text-[var(--color-text-secondary)] hover:border-[var(--color-accent)]/40 hover:text-[var(--color-text-primary)]"
            }`}
          >
            All events
          </button>
          {KNOWN_EVENT_TYPES.map((et) => {
            const active = selectedTypes.includes(et)
            return (
              <button
                key={et}
                type="button"
                onClick={() => toggleType(et)}
                className={`rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ${
                  active
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                    : "border-[var(--color-border)] text-[var(--color-text-secondary)] hover:border-[var(--color-accent)]/40 hover:text-[var(--color-text-primary)]"
                }`}
              >
                {et}
              </button>
            )
          })}
        </div>
      </div>

      {/* Min severity */}
      <div>
        <label
          htmlFor="event-filter-severity"
          className="block text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-text-secondary)] mb-1.5"
        >
          Minimum severity
        </label>
        <select
          id="event-filter-severity"
          value={value.min_severity ?? ""}
          onChange={(e) => setSeverity(e.target.value)}
          className="w-full max-w-xs rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-input)] px-3 py-2 text-sm text-[var(--color-text-primary)] focus:border-[var(--color-accent)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)]"
        >
          {SEVERITY_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        {value.min_severity && (
          <p className={`mt-1 text-[11px] font-medium ${SEVERITY_COLORS[value.min_severity] ?? ""}`}>
            Filtering: {value.min_severity} and above
          </p>
        )}
      </div>
    </div>
  )
}
