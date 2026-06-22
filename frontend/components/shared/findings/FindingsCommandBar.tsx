"use client"

import { useMemo } from "react"

import { CommandBar, type AttributeDef } from "@/components/shared/command-bar"
import { listAssignableUsers } from "@/lib/client/findings-api"

import { FindingsDisplayOverflow, type GroupKey } from "./FindingsDisplayOverflow"
import type { FindingsMoreFiltersValues } from "./FindingsMoreFiltersPopover"
import type { AgePresetKey } from "./FindingsAgeFilter"
import type { SortKey } from "./FindingsSortDropdown"

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
    key: "tool",
    label: "tool",
    group: "Origin",
    description: "SCA · SAST · Containers · Secrets · IaC",
    type: "enum",
    options: [
      { value: "dependencies_scanning", label: "SCA" },
      { value: "code_scanning", label: "SAST" },
      { value: "container_scanning", label: "Container" },
      { value: "secret_scanning", label: "Secrets" },
      { value: "iac_scanning", label: "IaC" },
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
    key: "risk_score",
    label: "risk_score",
    group: "Risk signals",
    description: "Computed risk score threshold",
    type: "numeric",
    numeric: { min: 0, max: 100, step: 1 },
    placeholder: "70",
    displayValue: (raw) => `≥ ${raw}`,
  },
]

export interface FindingsCommandBarProps {
  /** Filter state. */
  severity: string
  scanner: string
  repo: string
  state: string
  moreFilters: FindingsMoreFiltersValues
  /** Filter setters. */
  onSeverityChange: (next: string) => void
  onScannerChange: (next: string) => void
  onRepoChange: (next: string) => void
  onStateChange: (next: string) => void
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
    tool: props.scanner === "all" ? null : props.scanner,
    repo: props.repo === "all" ? null : props.repo,
    state: props.state === "all" ? null : props.state,
    cwe: props.moreFilters.cwe,
    kev: props.moreFilters.kev ? "true" : null,
    epss: props.moreFilters.epssMin === null ? null : String(props.moreFilters.epssMin),
    risk_score:
      props.moreFilters.riskScoreMin === null ? null : String(props.moreFilters.riskScoreMin),
    assignee: props.moreFilters.assigneeUserId,
  }

  const handleChange = (key: string, value: string | null) => {
    switch (key) {
      case "severity":
        props.onSeverityChange(value ?? "all")
        break
      case "tool":
        props.onScannerChange(value ?? "all")
        break
      case "repo":
        props.onRepoChange(value ?? "all")
        break
      case "state":
        props.onStateChange(value ?? "all")
        break
      case "cwe":
        props.onMoreFiltersChange({ cwe: value })
        break
      case "epss":
        props.onMoreFiltersChange({ epssMin: value === null ? null : Number(value) })
        break
      case "risk_score":
        props.onMoreFiltersChange({ riskScoreMin: value === null ? null : Number(value) })
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
