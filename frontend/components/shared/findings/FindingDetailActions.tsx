"use client"

/**
 * Action button row for the findings detail drawer.
 *
 * All handlers are visual stubs today — when a prop is omitted we fall back
 * to a `console.log` no-op so each button keeps its keyboard, focus, and
 * aria semantics. Backend wiring lands in a follow-up.
 */

import type { ReactNode } from "react"

interface FindingDetailActionsProps {
  /** When an action is unavailable for this finding (e.g. no PR template),
   * pass `false` to render the button in a disabled state. Each defaults to
   * `true` so the row stays interactive by default. */
  canOpenFixPr?: boolean
  canCreateJira?: boolean
  canNotifySlack?: boolean
  canAssign?: boolean
  canDefer?: boolean
  onOpenFixPr?: () => void
  onCreateJira?: () => void
  onNotifySlack?: () => void
  onAssign?: () => void
  onDefer?: () => void
}

function stub(label: string) {
  return () => {
    // No-op stub — see component header for rationale.
    console.log(`[finding-actions] ${label} clicked`)
  }
}

function PrimaryButton({
  label,
  ariaLabel,
  icon,
  onClick,
  disabled,
}: {
  label: string
  ariaLabel: string
  icon: ReactNode
  onClick: () => void
  disabled?: boolean
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={ariaLabel}
      className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-semibold text-[var(--color-accent-on)] hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)]"
    >
      {icon}
      <span>{label}</span>
    </button>
  )
}

function GhostButton({
  label,
  ariaLabel,
  icon,
  onClick,
  disabled,
}: {
  label: string
  ariaLabel: string
  icon?: ReactNode
  onClick: () => void
  disabled?: boolean
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={ariaLabel}
      className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)] disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-1"
    >
      {icon}
      <span>{label}</span>
    </button>
  )
}

const IconPullRequest = (
  <svg
    width="13"
    height="13"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <circle cx="18" cy="18" r="3" />
    <circle cx="6" cy="6" r="3" />
    <path d="M13 6h3a2 2 0 0 1 2 2v7M6 9v12" />
  </svg>
)

const IconTicket = (
  <svg
    width="13"
    height="13"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="M20 7H4v13h16zM16 3v4M8 3v4M4 11h16" />
  </svg>
)

const IconBell = (
  <svg
    width="13"
    height="13"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="M14.857 17.082a23.848 23.848 0 0 0 5.454-1.31A8.967 8.967 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.967 8.967 0 0 1-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31" />
  </svg>
)

export function FindingDetailActions({
  canOpenFixPr = true,
  canCreateJira = true,
  canNotifySlack = true,
  canAssign = true,
  canDefer = true,
  onOpenFixPr,
  onCreateJira,
  onNotifySlack,
  onAssign,
  onDefer,
}: FindingDetailActionsProps) {
  return (
    <div
      role="group"
      aria-label="Finding actions"
      className="flex flex-wrap items-center gap-2 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-5 py-3"
    >
      <PrimaryButton
        label="Open fix PR"
        ariaLabel="Open a fix pull request for this finding"
        icon={IconPullRequest}
        onClick={onOpenFixPr ?? stub("open-fix-pr")}
        disabled={!canOpenFixPr}
      />
      <GhostButton
        label="Create Jira ticket"
        ariaLabel="Create a Jira ticket for this finding"
        icon={IconTicket}
        onClick={onCreateJira ?? stub("create-jira")}
        disabled={!canCreateJira}
      />
      <GhostButton
        label="Notify Slack"
        ariaLabel="Notify Slack about this finding"
        icon={IconBell}
        onClick={onNotifySlack ?? stub("notify-slack")}
        disabled={!canNotifySlack}
      />
      <GhostButton
        label="Assign"
        ariaLabel="Assign this finding to a teammate"
        onClick={onAssign ?? stub("assign")}
        disabled={!canAssign}
      />
      <GhostButton
        label="Defer"
        ariaLabel="Defer this finding"
        onClick={onDefer ?? stub("defer")}
        disabled={!canDefer}
      />
    </div>
  )
}
