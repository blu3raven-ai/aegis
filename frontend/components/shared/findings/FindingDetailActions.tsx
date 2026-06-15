"use client"

/**
 * Action button row for the findings detail drawer.
 *
 * All handlers are visual stubs today — when a prop is omitted we fall back
 * to a `console.log` no-op so each button keeps its keyboard, focus, and
 * aria semantics. Backend wiring lands in a follow-up.
 */

import type { ReactNode } from "react"
import { Button } from "@/components/ui/Button"

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

const IconPullRequest: ReactNode = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <circle cx="18" cy="18" r="3" />
    <circle cx="6" cy="6" r="3" />
    <path d="M13 6h3a2 2 0 0 1 2 2v7M6 9v12" />
  </svg>
)

const IconTicket: ReactNode = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M20 7H4v13h16zM16 3v4M8 3v4M4 11h16" />
  </svg>
)

const IconBell: ReactNode = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
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
      <Button
        variant="primary"
        size="sm"
        leadingIcon={IconPullRequest}
        onClick={onOpenFixPr ?? stub("open-fix-pr")}
        disabled={!canOpenFixPr}
        aria-label="Open a fix pull request for this finding"
      >
        Open fix PR
      </Button>
      <Button
        variant="secondary"
        size="sm"
        leadingIcon={IconTicket}
        onClick={onCreateJira ?? stub("create-jira")}
        disabled={!canCreateJira}
        aria-label="Create a Jira ticket for this finding"
      >
        Create Jira ticket
      </Button>
      <Button
        variant="secondary"
        size="sm"
        leadingIcon={IconBell}
        onClick={onNotifySlack ?? stub("notify-slack")}
        disabled={!canNotifySlack}
        aria-label="Notify Slack about this finding"
      >
        Notify Slack
      </Button>
      <Button
        variant="secondary"
        size="sm"
        onClick={onAssign ?? stub("assign")}
        disabled={!canAssign}
        aria-label="Assign this finding to a teammate"
      >
        Assign
      </Button>
      <Button
        variant="secondary"
        size="sm"
        onClick={onDefer ?? stub("defer")}
        disabled={!canDefer}
        aria-label="Defer this finding"
      >
        Defer
      </Button>
    </div>
  )
}
