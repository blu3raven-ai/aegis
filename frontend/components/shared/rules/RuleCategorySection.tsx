"use client"

import type { RuleCategory, RuleSummary } from "@/lib/client/rules-api"
import { RuleRow } from "./RuleRow"
import { Button } from "@/components/ui/Button"

interface RuleCategorySectionProps {
  category: RuleCategory
  title: string
  subtitle: string
  icon: React.ReactNode
  rules: RuleSummary[]
  loading?: boolean
  onEdit?: (rule: RuleSummary) => void
  onToggle?: (rule: RuleSummary) => void
  onDelete?: (rule: RuleSummary) => void
  onCreate?: (category: RuleCategory) => void
  canManage: boolean
  disabled?: boolean
  placeholderText?: string
  scrollAnchorId?: string
}

// why: section icons act as visual anchors for each policy family;
// keep colour mapping centralised here so the four rules sections stay
// in lock-step even if their composition changes.
const ICON_THEME: Record<string, { color: string; bg: string }> = {
  sla: {
    color: "text-[var(--color-severity-critical)]",
    bg: "bg-[var(--color-severity-critical-subtle)]",
  },
  scanner_coverage: {
    color: "text-[var(--color-accent)]",
    bg: "bg-[var(--color-accent-subtle)]",
  },
  auto_dismiss: {
    color: "text-[var(--color-severity-medium)]",
    bg: "bg-[var(--color-severity-medium-subtle)]",
  },
  data_retention: {
    color: "text-[var(--color-state-dismissed)]",
    bg: "bg-[var(--color-state-dismissed-subtle)]",
  },
}

const DEFAULT_ICON_THEME = {
  color: "text-[var(--color-text-secondary)]",
  bg: "bg-[var(--color-surface-raised)]",
}

function SkeletonRow() {
  return (
    <div className="flex items-start gap-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3">
      <div className="flex-1 space-y-2">
        <div className="h-3.5 w-1/3 animate-pulse rounded bg-[var(--color-surface-raised)]" />
        <div className="h-3 w-1/2 animate-pulse rounded bg-[var(--color-surface-raised)]" />
        <div className="h-2.5 w-1/4 animate-pulse rounded bg-[var(--color-surface-raised)]" />
      </div>
      <div className="h-5 w-9 animate-pulse rounded-full bg-[var(--color-surface-raised)]" />
    </div>
  )
}

export function RuleCategorySection({
  category,
  title,
  subtitle,
  icon,
  rules,
  loading = false,
  onEdit,
  onToggle,
  onDelete,
  onCreate,
  canManage,
  disabled = false,
  placeholderText,
  scrollAnchorId,
}: RuleCategorySectionProps) {
  const showCreateButton = !disabled && canManage
  const iconTheme = ICON_THEME[category] ?? DEFAULT_ICON_THEME

  return (
    <section id={scrollAnchorId} className="space-y-3">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2.5">
          <span
            className={`flex h-7 w-7 items-center justify-center rounded-lg ${iconTheme.bg} ${iconTheme.color}`}
            aria-hidden
          >
            {icon}
          </span>
          <h2 className="text-base font-semibold text-[var(--color-text-primary)]">{title}</h2>
        </div>
        <span className="text-xs text-[var(--color-text-secondary)]">{subtitle}</span>
        {showCreateButton && (
          <Button
            variant="secondary"
            size="xs"
            onClick={() => onCreate?.(category)}
            className="ml-auto"
          >
            + New rule
          </Button>
        )}
      </div>

      {disabled ? (
        <div className="rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-6 text-center text-xs text-[var(--color-text-tertiary)]">
          {placeholderText ?? "Coming soon."}
        </div>
      ) : loading ? (
        <div className="space-y-2">
          <SkeletonRow />
          <SkeletonRow />
          <SkeletonRow />
        </div>
      ) : rules.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-surface)] py-10 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]">
            <svg
              className="h-6 w-6"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={1.2}
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 0 1 0 .255c-.008.378.137.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 0 1 0-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281Z" />
              <path d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />
            </svg>
          </div>
          <div className="flex flex-col gap-1">
            <p className="text-base font-semibold text-[var(--color-text-primary)]">
              No {title.toLowerCase()} yet
            </p>
            <p className="text-sm text-[var(--color-text-secondary)]">
              The default tiers should auto-create on first sync.
            </p>
          </div>
          {showCreateButton && (
            <Button
              variant="secondary"
              size="md"
              onClick={() => onCreate?.(category)}
            >
              Create rule
            </Button>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {rules.map((rule) => (
            <RuleRow
              key={rule.id}
              rule={rule}
              onEdit={onEdit}
              onToggle={onToggle}
              onDelete={onDelete}
              canManage={canManage}
            />
          ))}
        </div>
      )}
    </section>
  )
}
