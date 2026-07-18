"use client"

/**
 * Recursive condition tree builder for rules (notification routing, SLA, etc.).
 *
 * Renders an all/any group with nested child nodes. Each leaf has a
 * field selector, operator selector, and value input. Groups can be
 * nested to arbitrary depth — the tree mirrors the JSONB structure
 * evaluated server-side.
 *
 * Field options and value suggestions are supplied via the `fields` prop
 * so this component is reusable across different rule categories.
 */

import type { Condition, ConditionOp, LeafCondition } from "@/lib/rules-engine/conditions"
import type { ConditionFieldSchema } from "@/lib/rules-engine/field-schemas"
import { Button } from "@/components/ui/Button"
import { Card } from "@/components/ui/Card"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"


const OP_OPTIONS: { value: ConditionOp; label: string }[] = [
  { value: "eq", label: "equals" },
  { value: "neq", label: "not equals" },
  { value: "in", label: "in list" },
  { value: "nin", label: "not in list" },
  { value: "contains", label: "contains" },
  { value: "not_contains", label: "does not contain" },
  { value: "gt", label: "greater than" },
  { value: "gte", label: "greater than or equal" },
  { value: "lt", label: "less than" },
  { value: "lte", label: "less than or equal" },
]

// Multi-value operators that take a comma-separated value string
const MULTI_VALUE_OPS: ConditionOp[] = ["in", "nin"]

function isListOp(op: ConditionOp): boolean {
  return MULTI_VALUE_OPS.includes(op)
}

function parseCsvValue(raw: string): string | string[] {
  const parts = raw.split(",").map((s) => s.trim()).filter(Boolean)
  return parts.length > 1 ? parts : (parts[0] ?? "")
}

function valueToInput(val: string | string[] | number | boolean): string {
  if (Array.isArray(val)) return val.join(", ")
  if (val === null || val === undefined) return ""
  return String(val)
}


interface LeafNodeProps {
  cond: LeafCondition
  onChange: (c: Condition) => void
  onRemove: () => void
  fields: ConditionFieldSchema[]
  operatorsForField?: (fieldKey: string) => ConditionOp[]
}

function LeafNode({ cond, onChange, onRemove, fields, operatorsForField }: LeafNodeProps) {
  const field = cond.field
  const op = cond.op
  const rawVal = valueToInput(cond.value)

  const fieldSchema = fields.find((f) => f.value === field)

  const availableOps = operatorsForField ? operatorsForField(field) : null
  const filteredOps = availableOps
    ? OP_OPTIONS.filter((o) => availableOps.includes(o.value))
    : OP_OPTIONS
  // If the caller's operatorsForField returns an empty list, fall back to the
  // full set so the operator select is never rendered empty.
  const opOptions = filteredOps.length > 0 ? filteredOps : OP_OPTIONS

  function setField(f: string) {
    onChange({ ...cond, field: f })
  }

  function setOp(o: ConditionOp) {
    // When switching from multi to single or vice versa, normalize the value
    const newVal = isListOp(o)
      ? (Array.isArray(cond.value) ? cond.value : [String(cond.value)])
      : (Array.isArray(cond.value) ? (cond.value[0] ?? "") : cond.value)
    onChange({ ...cond, op: o, value: newVal })
  }

  const suggestions = fieldSchema?.valueSuggestions ?? []
  const inputType = fieldSchema?.inputType ?? "text"

  function setValue(raw: string) {
    if (isListOp(op)) {
      // List ops always store string arrays — no type coercion in V1
      onChange({ ...cond, value: parseCsvValue(raw) })
      return
    }
    if (inputType === "boolean") {
      onChange({ ...cond, value: raw === "true" })
      return
    }
    if (inputType === "number") {
      if (raw === "") {
        onChange({ ...cond, value: "" })
        return
      }
      const n = Number(raw)
      onChange({ ...cond, value: Number.isNaN(n) ? raw : n })
      return
    }
    onChange({ ...cond, value: raw })
  }

  // Render the value input based on inputType and operator
  function renderValueInput() {
    // Boolean fields: always render a select with true/false
    if (inputType === "boolean") {
      return (
        <Select
          size="sm"
          aria-label="value"
          value={rawVal}
          onChange={(e) => setValue(e.target.value)}
          className="w-auto"
        >
          <option value="">— select —</option>
          <option value="true">true</option>
          <option value="false">false</option>
        </Select>
      )
    }

    // Select/text fields with suggestions: show dropdown unless using a list op
    if (suggestions.length > 0 && !isListOp(op)) {
      return (
        <Select
          size="sm"
          aria-label="value"
          value={rawVal}
          onChange={(e) => setValue(e.target.value)}
          className="w-auto"
        >
          <option value="">— select —</option>
          {suggestions.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </Select>
      )
    }

    // Number input
    if (inputType === "number" && !isListOp(op)) {
      return (
        <Input
          size="sm"
          aria-label="value"
          type="number"
          value={rawVal}
          onChange={(e) => setValue(e.target.value)}
          placeholder="value"
          className="min-w-[100px] w-auto"
        />
      )
    }

    // Default: free text
    return (
      <Input
        size="sm"
        aria-label="value"
        type="text"
        value={rawVal}
        onChange={(e) => setValue(e.target.value)}
        placeholder={isListOp(op) ? "val1, val2, …" : "value"}
        className="min-w-[120px] w-auto"
      />
    )
  }

  return (
    <Card padding="none" className="flex flex-wrap items-center gap-2 px-3 py-2">
      {/* Field */}
      <Select
        size="sm"
        aria-label="field"
        value={field}
        onChange={(e) => setField(e.target.value)}
        className="w-auto"
      >
        {fields.map((f) => (
          <option key={f.value} value={f.value}>{f.label}</option>
        ))}
      </Select>

      {/* Operator */}
      <Select
        size="sm"
        aria-label="operator"
        value={op}
        onChange={(e) => setOp(e.target.value as ConditionOp)}
        className="w-auto"
      >
        {opOptions.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </Select>

      {/* Value */}
      {renderValueInput()}

      {/* Remove */}
      <Button
        variant="ghost"
        size="xs"
        iconOnly
        onClick={onRemove}
        aria-label="remove condition"
        className="ml-auto hover:bg-[var(--color-severity-critical)]/10 hover:text-[var(--color-severity-critical-text)]"
      >
        ×
      </Button>
    </Card>
  )
}


interface GroupNodeProps {
  cond: { all?: Condition[]; any?: Condition[] }
  onChange: (c: Condition) => void
  onRemove?: () => void
  depth?: number
  fields: ConditionFieldSchema[]
  operatorsForField?: (fieldKey: string) => ConditionOp[]
}

function GroupNode({ cond, onChange, onRemove, depth = 0, fields, operatorsForField }: GroupNodeProps) {
  const isAll = "all" in cond
  const children: Condition[] = (isAll ? cond.all : cond.any) ?? []
  const groupKey = isAll ? "all" : "any"

  function update(newChildren: Condition[]) {
    onChange({ [groupKey]: newChildren } as Condition)
  }

  function toggleGroupType() {
    const nextKey = isAll ? "any" : "all"
    onChange({ [nextKey]: children } as Condition)
  }

  function addLeaf() {
    const firstField = fields[0]
    const fieldKey = firstField?.value ?? ""
    let defaultValue: string | number | boolean = ""
    if (firstField?.valueSuggestions && firstField.valueSuggestions.length > 0) {
      defaultValue = firstField.valueSuggestions[0]
    } else if (firstField?.inputType === "boolean") {
      defaultValue = true
    }
    update([
      ...children,
      { field: fieldKey, op: "eq" as ConditionOp, value: defaultValue },
    ])
  }

  function addGroup() {
    update([...children, { all: [] }])
  }

  function updateChild(i: number, child: Condition) {
    const next = [...children]
    next[i] = child
    update(next)
  }

  function removeChild(i: number) {
    update(children.filter((_, idx) => idx !== i))
  }

  return (
    <div
      className={`rounded-xl border ${
        depth === 0
          ? "border-[var(--color-border)]"
          : "border-[var(--color-border-divider)]"
      } bg-[var(--color-surface)] p-3 space-y-2`}
    >
      {/* Group header */}
      <div className="flex items-center gap-2">
        <Button
          variant="secondary"
          size="xs"
          onClick={toggleGroupType}
          className="border-[var(--color-accent)]/40 bg-[var(--color-accent)]/10 text-[var(--color-accent)] hover:bg-[var(--color-accent)]/20 hover:border-[var(--color-accent)]/40"
        >
          {isAll ? "ALL of" : "ANY of"}
        </Button>
        <span className="text-xs text-[var(--color-text-tertiary)]">
          {isAll ? "(AND: all conditions must match)" : "(OR: at least one must match)"}
        </span>
        {onRemove && (
          <Button
            variant="ghost"
            size="xs"
            iconOnly
            onClick={onRemove}
            aria-label="remove group"
            className="ml-auto hover:bg-[var(--color-severity-critical)]/10 hover:text-[var(--color-severity-critical-text)]"
          >
            ×
          </Button>
        )}
      </div>

      {/* Children */}
      <div className={`space-y-2 ${depth > 0 ? "pl-3 border-l border-[var(--color-border-divider)]" : ""}`}>
        {children.length === 0 && (
          <p className="text-xs text-[var(--color-text-tertiary)] italic px-1">
            No conditions — add one below.
          </p>
        )}
        {children.map((child, i) => {
          if ("all" in child || "any" in child) {
            return (
              <GroupNode
                key={i}
                cond={child as { all?: Condition[]; any?: Condition[] }}
                onChange={(c) => updateChild(i, c)}
                onRemove={() => removeChild(i)}
                depth={depth + 1}
                fields={fields}
                operatorsForField={operatorsForField}
              />
            )
          }
          return (
            <LeafNode
              key={i}
              cond={child as LeafCondition}
              onChange={(c) => updateChild(i, c)}
              onRemove={() => removeChild(i)}
              fields={fields}
              operatorsForField={operatorsForField}
            />
          )
        })}
      </div>

      {/* Add buttons */}
      <div className="flex items-center gap-2 pt-1">
        <Button
          variant="secondary"
          size="xs"
          onClick={addLeaf}
        >
          + Condition
        </Button>
        {depth < 3 && (
          <Button
            variant="secondary"
            size="xs"
            onClick={addGroup}
          >
            + Group
          </Button>
        )}
      </div>
    </div>
  )
}


export interface ConditionBuilderProps {
  value: Condition
  onChange: (c: Condition) => void
  fields: ConditionFieldSchema[]
  /** Optional: restrict operators per field. Falls back to full operator list. */
  operatorsForField?: (fieldKey: string) => ConditionOp[]
}

export function ConditionBuilder({ value, onChange, fields, operatorsForField }: ConditionBuilderProps) {
  // Normalise the root to always be an all/any group
  const root = ("all" in value || "any" in value)
    ? (value as { all?: Condition[]; any?: Condition[] })
    : { all: [] as Condition[] }

  return <GroupNode cond={root} onChange={onChange} depth={0} fields={fields} operatorsForField={operatorsForField} />
}
