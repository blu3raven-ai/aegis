"use client"

import type { RuleSummary } from "@/lib/client/rules-api"
import type { Condition, LeafCondition } from "@/lib/rules-engine/conditions"
import { summarizeAction } from "@/lib/rules-engine/display"
import { relativeTime } from "@/lib/shared/relative-time"
import { Button } from "@/components/ui/Button"

interface RuleRowProps {
  rule: RuleSummary
  onEdit?: (rule: RuleSummary) => void
  onToggle?: (rule: RuleSummary) => void
  onDelete?: (rule: RuleSummary) => void
  canManage: boolean
}

const OP_LABEL: Record<string, string> = {
  eq: "=",
  neq: "!=",
  in: "in",
  nin: "not in",
  contains: "contains",
  not_contains: "does not contain",
  gt: ">",
  gte: ">=",
  lt: "<",
  lte: "<=",
}

function isLeaf(c: Condition): c is LeafCondition {
  return (
    typeof c === "object" &&
    c !== null &&
    "field" in c &&
    "op" in c &&
    "value" in c
  )
}

function formatLeaf(leaf: LeafCondition): string {
  const op = OP_LABEL[leaf.op] ?? leaf.op
  const value = Array.isArray(leaf.value)
    ? `(${leaf.value.join(", ")})`
    : String(leaf.value)
  return `${leaf.field} ${op} ${value}`
}

function summarizeConditions(conditions: Condition): string {
  if (!conditions || Object.keys(conditions).length === 0) return "any subject"
  if (isLeaf(conditions)) return formatLeaf(conditions)

  if ("all" in conditions && Array.isArray(conditions.all)) {
    const children = conditions.all
    if (children.length === 1 && isLeaf(children[0])) return formatLeaf(children[0])
    if (children.every(isLeaf)) {
      return children.map(formatLeaf).join(" AND ")
    }
    return "complex conditions"
  }

  if ("any" in conditions && Array.isArray(conditions.any)) {
    const children = conditions.any
    if (children.length === 1 && isLeaf(children[0])) return formatLeaf(children[0])
    if (children.every(isLeaf)) {
      return children.map(formatLeaf).join(" OR ")
    }
    return "complex conditions"
  }

  return "complex conditions"
}

function formatCreatedAt(iso: string): string {
  return relativeTime(iso)
}

export function RuleRow({ rule, onEdit, onToggle, onDelete, canManage }: RuleRowProps) {
  const violationsOpen = rule.violation_count_open
  const showViolationsLink = violationsOpen > 0
  const hasViolations = rule.enabled && violationsOpen > 0
  const isPaused = !rule.enabled

  const conditionText = summarizeConditions(rule.conditions)
  const actionText = summarizeAction(rule.action)

  function handleDeleteClick() {
    if (!onDelete) return
    if (!window.confirm(`Delete rule "${rule.name}"? This cannot be undone.`)) return
    onDelete(rule)
  }

  // why: a card with open violations should read as a warning surface at
  // a glance — mirror the mock by tinting the border amber; a paused card
  // recedes via opacity so the eye skips over it.
  const cardClass = [
    "flex items-start gap-4 rounded-md border bg-[var(--color-surface)] px-4 py-3 transition-colors",
    hasViolations
      ? "border-[var(--color-severity-medium-border)]"
      : "border-[var(--color-border)]",
    isPaused ? "opacity-60" : "",
  ]
    .filter(Boolean)
    .join(" ")

  return (
    <div className={cardClass}>
      <div className="flex-1 min-w-0 space-y-1.5">
        {/* Name + status pills */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="text-sm font-semibold text-[var(--color-text-primary)]">
            {rule.name}
          </div>

          {rule.enabled && (
            <span
              className="inline-flex items-center gap-1 rounded bg-[var(--color-state-fixed)]/10 px-1.5 py-0.5 text-2xs font-mono font-bold uppercase tracking-wider text-[var(--color-state-fixed-text)]"
            >
              Active
            </span>
          )}

          {rule.enabled && violationsOpen > 0 && (
            <span
              className="inline-flex items-center gap-1 rounded-full bg-[var(--color-severity-critical)]/10 px-2 py-0.5 text-xs font-semibold text-[var(--color-severity-critical-text)]"
            >
              {violationsOpen} violation{violationsOpen === 1 ? "" : "s"}
            </span>
          )}

          {!rule.enabled && (
            <span
              className="inline-flex items-center gap-1 rounded bg-[var(--color-surface-raised)] px-1.5 py-0.5 text-2xs font-mono font-bold uppercase tracking-wider text-[var(--color-text-tertiary)]"
            >
              Paused
            </span>
          )}
        </div>

        {/* Condition → action (mock policy-rule: cond as inline mono pill, arrow, target text) */}
        <div className="flex flex-wrap items-center gap-2 text-sm text-[var(--color-text-secondary)]">
          <span className="inline-flex items-center rounded bg-[var(--color-surface-raised)] px-2 py-0.5 font-[family-name:var(--font-jetbrains-mono)] text-[11.5px] text-[var(--color-text-primary)]">
            {conditionText}
          </span>
          <span aria-hidden className="text-[var(--color-text-tertiary)]">→</span>
          <span>{actionText}</span>
        </div>

        {/* Meta row */}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[var(--color-text-tertiary)]">
          <span>
            Applies to all repos · created {formatCreatedAt(rule.created_at)} by {rule.created_by}
          </span>
          {showViolationsLink && (
            <Button
              variant="link"
              size="xs"
              disabled
              aria-disabled="true"
              title="Coming soon"
              aria-label="View violations — coming soon"
              className="cursor-not-allowed text-[var(--color-text-tertiary)] underline-offset-2 disabled:opacity-60"
            >
              View violations →
            </Button>
          )}
        </div>
      </div>

      {canManage && (
        <div className="flex items-center gap-2">
          {/* Toggle switch */}
          <button
            type="button"
            role="switch"
            aria-checked={rule.enabled}
            onClick={() => onToggle?.(rule)}
            className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] ${
              rule.enabled ? "bg-[var(--color-accent)]" : "bg-[var(--color-surface-raised)] border border-[var(--color-border)]"
            }`}
            aria-label={`Toggle rule ${rule.name}`}
          >
            <span
              className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
                rule.enabled ? "translate-x-4" : "translate-x-1"
              }`}
            />
          </button>

          <Button
            variant="ghost"
            size="xs"
            onClick={() => onEdit?.(rule)}
            className="text-[var(--color-accent)] hover:text-[var(--color-accent)] hover:bg-[var(--color-accent-subtle)]"
          >
            Edit
          </Button>
          <Button
            variant="ghost"
            size="xs"
            onClick={handleDeleteClick}
            className="text-[var(--color-severity-critical-text)] hover:text-[var(--color-severity-critical-text)] hover:bg-[var(--color-severity-critical-subtle)]"
          >
            Delete
          </Button>
        </div>
      )}
    </div>
  )
}
