"use client"

import { useEffect, useMemo, useRef, useState } from "react"

import { CommandBar, type AttributeDef, type CustomPickerProps } from "@/components/shared/command-bar"
import { listAssignableUsers } from "@/lib/client/findings-api"
import { Button } from "@/components/ui/Button"
import { FilterChip } from "@/components/ui/FilterChip"

import { FindingsDisplayOverflow, type GroupKey } from "./FindingsDisplayOverflow"
import type { FindingsMoreFiltersValues } from "./FindingsMoreFiltersPopover"
import type { AgePresetKey } from "./FindingsAgeFilter"
import type { SortKey } from "./FindingsSortDropdown"
import type { FindingActionBand } from "@/lib/shared/findings/row-mapper"

const STATIC_ATTRIBUTES: AttributeDef[] = [
  {
    key: "severity",
    label: "severity",
    group: "Triage",
    description: "Critical · High · Medium · Low",
    type: "enum",
    options: [
      { value: "critical", label: "Critical", dotColor: "var(--color-severity-critical)" },
      { value: "high", label: "High", dotColor: "var(--color-severity-high)" },
      { value: "medium", label: "Medium", dotColor: "var(--color-severity-medium)" },
      { value: "low", label: "Low", dotColor: "var(--color-severity-low)" },
    ],
  },
  {
    key: "state",
    label: "state",
    group: "Triage",
    description: "Open · Closed · Fixed · Dismissed",
    type: "enum",
    options: [
      { value: "open", label: "Open" },
      { value: "closed", label: "Closed" },
      { value: "fixed", label: "Fixed" },
      { value: "dismissed", label: "Dismissed" },
    ],
  },
  {
    key: "assignee",
    label: "assignee",
    group: "Triage",
    description: "User assigned to triage",
    type: "async-list",
    asyncLoader: async (q) => {
      const users = await listAssignableUsers(q || null, 20)
      return users.map((u) => ({ value: u.id, label: u.username }))
    },
  },
  {
    key: "scanner",
    label: "scanner",
    group: "Origin",
    description: "Which scanner surfaced the finding",
    type: "enum",
    options: [
      { value: "dependencies_scanning", label: "Dependencies" },
      { value: "code_scanning", label: "Code Scanning" },
      { value: "container_scanning", label: "Containers" },
      { value: "secret_scanning", label: "Secrets" },
      { value: "iac_scanning", label: "Infrastructure as Code" },
      { value: "agent_scanning", label: "Coding Agent Scanning" },
      { value: "deep_audit", label: "Deep Audit" },
    ],
  },
  {
    key: "cwe",
    label: "cwe",
    group: "Origin",
    description: "CWE identifier",
    type: "text",
    placeholder: "CWE-79",
  },
  {
    key: "kev",
    label: "kev",
    group: "Risk signals",
    description: "In CISA KEV catalogue",
    type: "boolean",
    variant: "danger",
    options: [
      { value: "true", label: "Yes" },
      { value: "false", label: "No" },
    ],
  },
  {
    key: "epss",
    label: "epss",
    group: "Risk signals",
    description: "EPSS percentile threshold",
    type: "numeric",
    numeric: { min: 0, max: 1, step: 0.01 },
    placeholder: "0.7",
    displayValue: (raw) => `≥ ${raw}`,
  },
  {
    key: "bands",
    label: "action band",
    group: "Risk signals",
    description: "SSVC action band: Act · Attend · Track",
    type: "enum",
    options: [
      { value: "act", label: "Act" },
      { value: "attend", label: "Attend" },
      { value: "track", label: "Track" },
    ],
    // The picker is multi-select, so render the active chip from the CSV the
    // band values carry rather than a single option label.
    displayValue: (csv) =>
      csv
        .split(",")
        .map((v) => BAND_LABELS[v] ?? v)
        .join(", "),
  },
]

const BAND_LABELS: Record<string, string> = { act: "Act", attend: "Attend", track: "Track" }

// Chip ordering + tone for the multi-select picker, kept in band-severity order.
const BAND_OPTIONS: { value: FindingActionBand; label: string; tone?: "accent" | "danger" }[] = [
  { value: "act", label: "Act", tone: "danger" },
  { value: "attend", label: "Attend", tone: "accent" },
  { value: "track", label: "Track" },
]

function parseBands(csv: string | null): FindingActionBand[] {
  if (!csv) return []
  const seen = new Set(csv.split(","))
  return BAND_OPTIONS.map((b) => b.value).filter((b) => seen.has(b))
}

/**
 * Multi-select picker for the action-band filter. The command bar's stock enum
 * picker is single-select, so bands ships its own picker via `customPickers`.
 * Toggles accumulate in a local draft and commit together on Apply — committing
 * also closes the picker, which is why each toggle can't commit on its own.
 */
function BandMultiPicker({ value, onApply, onClose }: CustomPickerProps) {
  const rootRef = useRef<HTMLDivElement>(null)
  const [draft, setDraft] = useState<Set<FindingActionBand>>(() => new Set(parseBands(value)))

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) onClose()
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose()
    }
    document.addEventListener("mousedown", onClick)
    document.addEventListener("keydown", onKey)
    return () => {
      document.removeEventListener("mousedown", onClick)
      document.removeEventListener("keydown", onKey)
    }
  }, [onClose])

  const toggle = (band: FindingActionBand) => {
    setDraft((prev) => {
      const next = new Set(prev)
      if (next.has(band)) next.delete(band)
      else next.add(band)
      return next
    })
  }

  const commit = () => {
    const ordered = BAND_OPTIONS.map((b) => b.value).filter((b) => draft.has(b))
    onApply(ordered.length ? ordered.join(",") : null)
  }

  return (
    <div
      ref={rootRef}
      role="dialog"
      aria-label="Set action band"
      className="absolute left-0 top-full z-50 mt-1 w-56 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-2 shadow-lg"
    >
      <div className="mb-1 px-1 font-mono text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-tertiary)]">
        action band
      </div>
      <div className="flex flex-wrap gap-1.5 p-1">
        {BAND_OPTIONS.map((b) => (
          <FilterChip
            key={b.value}
            label={b.label}
            tone={b.tone}
            active={draft.has(b.value)}
            onClick={() => toggle(b.value)}
          />
        ))}
      </div>
      <div className="mt-2 flex justify-end gap-1">
        <Button variant="ghost" size="xs" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="primary" size="xs" onClick={commit}>
          Apply
        </Button>
      </div>
    </div>
  )
}

export interface FindingsCommandBarProps {
  /** Filter state. "all" means the filter is inactive. */
  severity: string
  repo: string
  state: string
  scanner: string
  moreFilters: FindingsMoreFiltersValues
  /** Filter setters. */
  onSeverityChange: (next: string) => void
  onRepoChange: (next: string) => void
  onStateChange: (next: string) => void
  onScannerChange: (next: string) => void
  onMoreFiltersChange: (patch: Partial<FindingsMoreFiltersValues>) => void

  searchInput: string
  onSearchInputChange: (next: string) => void
  onSearchSubmit: () => void
  searchQuery: string
  onSearchClear: () => void

  groupBy: GroupKey
  sortKey: SortKey
  agePreset: AgePresetKey
  onGroupByChange: (next: GroupKey) => void
  onSortKeyChange: (next: SortKey) => void
  onAgePresetChange: (next: AgePresetKey) => void

  /** Repo slugs for the value picker. */
  repoOptions: string[]
}

export function FindingsCommandBar(props: FindingsCommandBarProps) {
  // Repo options change at runtime, so we extend the static catalogue here.
  const attributes = useMemo<AttributeDef[]>(() => {
    const repoOptions = props.repoOptions.map((slug) => ({ value: slug, label: slug }))
    return [
      ...STATIC_ATTRIBUTES,
      {
        key: "repo",
        label: "repo",
        group: "Origin",
        description: "Repository",
        type: "enum",
        options: repoOptions,
      },
    ]
  }, [props.repoOptions])

  const values: Record<string, string | null> = {
    severity: props.severity === "all" ? null : props.severity,
    repo: props.repo === "all" ? null : props.repo,
    state: props.state === "all" ? null : props.state,
    scanner: props.scanner === "all" ? null : props.scanner,
    cwe: props.moreFilters.cwe,
    kev: props.moreFilters.kev ? "true" : null,
    epss: props.moreFilters.epssMin === null ? null : String(props.moreFilters.epssMin),
    bands: props.moreFilters.bands.length ? props.moreFilters.bands.join(",") : null,
    assignee: props.moreFilters.assigneeUserId,
  }

  const handleChange = (key: string, value: string | null) => {
    switch (key) {
      case "severity":
        props.onSeverityChange(value ?? "all")
        break
      case "repo":
        props.onRepoChange(value ?? "all")
        break
      case "state":
        props.onStateChange(value ?? "all")
        break
      case "scanner":
        props.onScannerChange(value ?? "all")
        break
      case "cwe":
        props.onMoreFiltersChange({ cwe: value })
        break
      case "epss":
        props.onMoreFiltersChange({ epssMin: value === null ? null : Number(value) })
        break
      case "bands":
        props.onMoreFiltersChange({ bands: value ? (value.split(",") as FindingActionBand[]) : [] })
        break
      case "assignee":
        props.onMoreFiltersChange({ assigneeUserId: value })
        break
      case "kev":
        props.onMoreFiltersChange({ kev: value === "true" })
        break
    }
  }

  return (
    <CommandBar
      attributes={attributes}
      values={values}
      onChange={handleChange}
      customPickers={{ bands: BandMultiPicker }}
      searchInput={props.searchInput}
      onSearchInputChange={props.onSearchInputChange}
      onSearchSubmit={props.onSearchSubmit}
      searchPlaceholder="Search findings…"
      displayOverflow={
        <FindingsDisplayOverflow
          groupBy={props.groupBy}
          sortKey={props.sortKey}
          agePreset={props.agePreset}
          onGroupByChange={props.onGroupByChange}
          onSortKeyChange={props.onSortKeyChange}
          onAgePresetChange={props.onAgePresetChange}
        />
      }
    />
  )
}
