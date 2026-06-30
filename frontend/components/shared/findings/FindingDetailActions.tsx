"use client"

/**
 * Action button row for the findings detail drawer.
 *
 * Each action renders only when it has a real handler. The Dismiss control is
 * the accessible DismissPopover primitive (Button-triggered role=menu).
 */

import type { ReactNode } from "react"
import { Button } from "@/components/ui/Button"
import { DismissPopover } from "@/components/shared/FindingDrawer/DismissPopover"

interface DismissControl {
  reasons: readonly string[]
  onDismiss: (reason: string) => void
  busy?: boolean
  error?: string | null
}

interface FindingDetailActionsProps {
  /** When an action is unavailable for this finding (e.g. no PR template),
   * pass `false` to render the button in a disabled state. Each defaults to
   * `true` so the row stays interactive by default. */
  canOpenFixPr?: boolean
  canCreateJira?: boolean
  canNotifySlack?: boolean
  canDefer?: boolean
  onOpenFixPr?: () => void
  onCreateJira?: () => void
  onNotifySlack?: () => void
  onDefer?: () => void
  /** Assignment is a disposition like Defer/Dismiss, so the real assignee
   *  picker lives here in the action row (rendered first). */
  assigneeControl?: ReactNode
  /** Real disposition control — dismiss the finding with a reason. */
  dismiss?: DismissControl
  /** For already-closed findings: reopen is the only useful disposition, so it
   *  replaces Defer/Dismiss (which the caller simply doesn't pass). */
  onReopen?: () => void
  reopenBusy?: boolean
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
  canDefer = true,
  onOpenFixPr,
  onCreateJira,
  onNotifySlack,
  onDefer,
  assigneeControl,
  dismiss,
  onReopen,
  reopenBusy,
}: FindingDetailActionsProps) {
  return (
    <div
      role="group"
      aria-label="Finding actions"
      className="flex flex-wrap items-center gap-2 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-5 py-3"
    >
      {assigneeControl}
      {/* Integration actions render only when actually wired to a handler —
          PR / Jira / Slack have no backend yet, so they stay hidden rather
          than masquerade as working buttons. */}
      {onOpenFixPr && (
        <Button
          variant="primary"
          size="sm"
          leadingIcon={IconPullRequest}
          onClick={onOpenFixPr}
          disabled={!canOpenFixPr}
          aria-label="Open a fix pull request for this finding"
        >
          Open fix PR
        </Button>
      )}
      {onCreateJira && (
        <Button
          variant="secondary"
          size="sm"
          leadingIcon={IconTicket}
          onClick={onCreateJira}
          disabled={!canCreateJira}
          aria-label="Create a Jira ticket for this finding"
        >
          Create Jira ticket
        </Button>
      )}
      {onNotifySlack && (
        <Button
          variant="secondary"
          size="sm"
          leadingIcon={IconBell}
          onClick={onNotifySlack}
          disabled={!canNotifySlack}
          aria-label="Notify Slack about this finding"
        >
          Notify Slack
        </Button>
      )}
      {onDefer && (
        <Button
          variant="secondary"
          size="sm"
          onClick={onDefer}
          disabled={!canDefer}
          aria-label="Defer this finding"
        >
          Defer
        </Button>
      )}

      {dismiss && (
        <div className="ml-auto flex items-center gap-2">
          {dismiss.error && (
            <span className="text-[11px] text-[var(--color-severity-high)]" role="alert">
              {dismiss.error}
            </span>
          )}
          <DismissPopover
            reasons={dismiss.reasons}
            onDismiss={dismiss.onDismiss}
            isLoading={Boolean(dismiss.busy)}
            triggerLabel={dismiss.busy ? "Dismissing…" : "Dismiss"}
            placement="bottom"
          />
        </div>
      )}

      {onReopen && (
        <div className="ml-auto">
          <Button
            variant="secondary"
            size="sm"
            onClick={onReopen}
            disabled={reopenBusy}
            aria-label="Reopen this finding"
          >
            {reopenBusy ? "Reopening…" : "Reopen"}
          </Button>
        </div>
      )}
    </div>
  )
}
