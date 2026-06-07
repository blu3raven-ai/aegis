import type { ComponentType, ReactNode } from "react"

export type AttributeType = "enum" | "boolean" | "numeric" | "text" | "async-list"

export interface EnumOption {
  value: string
  label: string
  /** Optional accent dot color for the value picker. */
  dotColor?: string
}

export interface NumericConstraints {
  min: number
  max: number
  step?: number
  placeholder?: string
}

export type AsyncOptionLoader = (query: string) => Promise<EnumOption[]>

export interface AttributeDef {
  /** Stable key used in values map and URL state. */
  key: string
  /** Short label shown in the chip and palette ("severity"). */
  label: string
  /** Section header in the attribute palette ("Triage"). */
  group: string
  /** Sub-line shown next to the field name in the palette. */
  description: string
  /** Picker dispatch type. */
  type: AttributeType
  /** Visual chip variant — use "danger" for binary risk signals. */
  variant?: "default" | "danger"
  /** Required for type "enum" and "boolean". */
  options?: EnumOption[]
  /** Required for type "numeric". */
  numeric?: NumericConstraints
  /** Required for type "async-list". */
  asyncLoader?: AsyncOptionLoader
  /** Placeholder text for "text" and "numeric" inputs. */
  placeholder?: string
  /** Optional formatter for the chip display ("≥ 0.7"). */
  displayValue?: (raw: string) => string
}

export interface CustomPickerProps {
  value: string | null
  onApply: (next: string | null) => void
  onClose: () => void
}

export interface CommandBarProps {
  /** Attribute catalog driving palette + chip rendering. */
  attributes: AttributeDef[]
  /** Current values keyed by attribute. null = not active. */
  values: Record<string, string | null>
  /** Setter invoked when a chip changes or is removed (value=null). */
  onChange: (key: string, value: string | null) => void
  /** Optional free-text search slot. Omit to hide the search input. */
  searchInput?: string
  onSearchInputChange?: (next: string) => void
  onSearchSubmit?: () => void
  searchPlaceholder?: string
  /** Optional page-specific overflow rendered to the right of the bar. */
  displayOverflow?: ReactNode
  /** Override the value picker for specific attribute keys. */
  customPickers?: Record<string, ComponentType<CustomPickerProps>>
}
