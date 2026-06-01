"use client"

/**
 * Recursive condition tree builder for notification routing rules.
 *
 * Renders an all/any group with nested child nodes. Each leaf has a
 * field selector, operator selector, and value input. Groups can be
 * nested to arbitrary depth — the tree mirrors the JSONB structure
 * evaluated server-side by routing.py.
 */

import type { Condition, ConditionOp, FindingField, LeafCondition } from "@/lib/client/notification-rules-api"

// ── Static option lists ───────────────────────────────────────────────────────

const FIELD_OPTIONS: { value: FindingField; label: string }[] = [
  { value: "severity", label: "Severity" },
  { value: "scanner", label: "Scanner" },
  { value: "repo_id", label: "Repository ID" },
  { value: "repo_labels", label: "Repo labels" },
  { value: "cve_id", label: "CVE ID" },
  { value: "chain_role", label: "Chain role" },
]

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

const SEVERITY_VALUES = ["critical", "high", "medium", "low", "info"]
const SCANNER_VALUES = ["dependencies", "code_scanning", "secrets", "container_scanning"]
const CHAIN_ROLE_VALUES = ["entrypoint", "pivot", "sink"]

// Multi-value operators that take a comma-separated value string
const MULTI_VALUE_OPS: ConditionOp[] = ["in", "nin"]

function isListOp(op: ConditionOp): boolean {
  return MULTI_VALUE_OPS.includes(op)
}

function parseCsvValue(raw: string): string | string[] {
  const parts = raw.split(",").map((s) => s.trim()).filter(Boolean)
  return parts.length > 1 ? parts : (parts[0] ?? "")
}

function valueToInput(val: string | string[]): string {
  return Array.isArray(val) ? val.join(", ") : (val ?? "")
}

// ── Leaf node ─────────────────────────────────────────────────────────────────

interface LeafNodeProps {
  cond: LeafCondition
  onChange: (c: Condition) => void
  onRemove: () => void
}

function LeafNode({ cond, onChange, onRemove }: LeafNodeProps) {
  const field = cond.field
  const op = cond.op
  const rawVal = valueToInput(cond.value)

  function setField(f: FindingField) {
    onChange({ ...cond, field: f })
  }

  function setOp(o: ConditionOp) {
    // When switching from multi to single or vice versa, normalize the value
    const newVal = isListOp(o)
      ? (Array.isArray(cond.value) ? cond.value : [String(cond.value)])
      : (Array.isArray(cond.value) ? (cond.value[0] ?? "") : cond.value)
    onChange({ ...cond, op: o, value: newVal })
  }

  function setValue(raw: string) {
    const parsed = isListOp(op) ? parseCsvValue(raw) : raw
    onChange({ ...cond, value: parsed })
  }

  // Suggest values based on the selected field
  const suggestions =
    field === "severity"
      ? SEVERITY_VALUES
      : field === "scanner"
        ? SCANNER_VALUES
        : field === "chain_role"
          ? CHAIN_ROLE_VALUES
          : []

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2">
      {/* Field */}
      <select
        aria-label="field"
        value={field}
        onChange={(e) => setField(e.target.value as FindingField)}
        className="rounded border border-[var(--color-border)] bg-[var(--color-bg-input)] px-2 py-1 text-xs text-[var(--color-text-primary)] focus:border-[var(--color-accent)] focus:outline-none"
      >
        {FIELD_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>

      {/* Operator */}
      <select
        aria-label="operator"
        value={op}
        onChange={(e) => setOp(e.target.value as ConditionOp)}
        className="rounded border border-[var(--color-border)] bg-[var(--color-bg-input)] px-2 py-1 text-xs text-[var(--color-text-primary)] focus:border-[var(--color-accent)] focus:outline-none"
      >
        {OP_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>

      {/* Value */}
      {suggestions.length > 0 && !isListOp(op) ? (
        <select
          aria-label="value"
          value={rawVal}
          onChange={(e) => setValue(e.target.value)}
          className="rounded border border-[var(--color-border)] bg-[var(--color-bg-input)] px-2 py-1 text-xs text-[var(--color-text-primary)] focus:border-[var(--color-accent)] focus:outline-none"
        >
          <option value="">— select —</option>
          {suggestions.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      ) : (
        <input
          aria-label="value"
          type="text"
          value={rawVal}
          onChange={(e) => setValue(e.target.value)}
          placeholder={isListOp(op) ? "val1, val2, …" : "value"}
          className="min-w-[120px] rounded border border-[var(--color-border)] bg-[var(--color-bg-input)] px-2 py-1 text-xs text-[var(--color-text-primary)] placeholder:text-[var(--color-text-tertiary)] focus:border-[var(--color-accent)] focus:outline-none"
        />
      )}

      {/* Remove */}
      <button
        type="button"
        onClick={onRemove}
        aria-label="remove condition"
        className="ml-auto rounded p-0.5 text-[var(--color-text-tertiary)] hover:bg-[var(--color-severity-critical)]/10 hover:text-[var(--color-severity-critical)]"
      >
        ×
      </button>
    </div>
  )
}

// ── Group node (all/any) ──────────────────────────────────────────────────────

interface GroupNodeProps {
  cond: { all?: Condition[]; any?: Condition[] }
  onChange: (c: Condition) => void
  onRemove?: () => void
  depth?: number
}

function GroupNode({ cond, onChange, onRemove, depth = 0 }: GroupNodeProps) {
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
    update([
      ...children,
      { field: "severity" as FindingField, op: "eq" as ConditionOp, value: "critical" },
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
        <button
          type="button"
          onClick={toggleGroupType}
          className="rounded-md border border-[var(--color-accent)]/40 bg-[var(--color-accent)]/10 px-2.5 py-1 text-xs font-semibold text-[var(--color-accent)] hover:bg-[var(--color-accent)]/20"
        >
          {isAll ? "ALL of" : "ANY of"}
        </button>
        <span className="text-xs text-[var(--color-text-tertiary)]">
          {isAll ? "(AND — all conditions must match)" : "(OR — at least one must match)"}
        </span>
        {onRemove && (
          <button
            type="button"
            onClick={onRemove}
            aria-label="remove group"
            className="ml-auto rounded p-0.5 text-[var(--color-text-tertiary)] hover:bg-[var(--color-severity-critical)]/10 hover:text-[var(--color-severity-critical)]"
          >
            ×
          </button>
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
              />
            )
          }
          return (
            <LeafNode
              key={i}
              cond={child as LeafCondition}
              onChange={(c) => updateChild(i, c)}
              onRemove={() => removeChild(i)}
            />
          )
        })}
      </div>

      {/* Add buttons */}
      <div className="flex items-center gap-2 pt-1">
        <button
          type="button"
          onClick={addLeaf}
          className="rounded-md border border-[var(--color-border)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)] hover:border-[var(--color-accent)]/40 hover:text-[var(--color-accent)]"
        >
          + Condition
        </button>
        {depth < 3 && (
          <button
            type="button"
            onClick={addGroup}
            className="rounded-md border border-[var(--color-border)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)] hover:border-[var(--color-accent)]/40 hover:text-[var(--color-accent)]"
          >
            + Group
          </button>
        )}
      </div>
    </div>
  )
}

// ── Public component ──────────────────────────────────────────────────────────

interface ConditionBuilderProps {
  value: Condition
  onChange: (c: Condition) => void
}

export function ConditionBuilder({ value, onChange }: ConditionBuilderProps) {
  // Normalise the root to always be an all/any group
  const root = ("all" in value || "any" in value)
    ? (value as { all?: Condition[]; any?: Condition[] })
    : { all: [] as Condition[] }

  return <GroupNode cond={root} onChange={onChange} depth={0} />
}
