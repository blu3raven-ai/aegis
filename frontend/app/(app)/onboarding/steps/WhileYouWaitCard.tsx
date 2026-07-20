"use client"

import Link from "next/link"

// Support / docs / community all resolve to the product site (same target the
// header CTAs use) until dedicated URLs exist.
const SUPPORT_URL = "https://blu3raven.ai/"

interface Task {
  title: string
  description: string
  icon: React.ReactNode
  href: string
}

function SlackIcon() {
  return (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M5 15a2 2 0 1 1-2-2h2v2zm1 0a2 2 0 1 1 4 0v5a2 2 0 1 1-4 0v-5zm2-8a2 2 0 1 1 2-2v2H8zm0 1a2 2 0 1 1 0 4H3a2 2 0 1 1 0-4h5zm8 2a2 2 0 1 1 2 2h-2V10zm-1 0a2 2 0 1 1-4 0V5a2 2 0 1 1 4 0v5zm-2 8a2 2 0 1 1-2 2v-2h2zm0-1a2 2 0 1 1 0-4h5a2 2 0 1 1 0 4h-5z" />
    </svg>
  )
}

function JiraIcon() {
  return (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M11.53 2c0 2.4 1.97 4.35 4.35 4.35h1.78v1.72c0 2.4 1.94 4.34 4.34 4.34V2.84A.84.84 0 0 0 21.16 2h-9.63z" />
    </svg>
  )
}

function TeamIcon() {
  return (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="8.5" cy="7" r="4" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M20 8v6M23 11h-6" />
    </svg>
  )
}

function TourIcon() {
  return (
    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M9.813 15.904 9 18.75l-.813-2.846a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 0 0-3.09 3.09Z"
      />
    </svg>
  )
}

function ChevronRight() {
  return (
    <svg className="h-3.5 w-3.5 shrink-0 self-center text-[var(--color-text-tertiary)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="m9 18 6-6-6-6" />
    </svg>
  )
}

const TASK_ROW_CLASSES =
  "flex items-start gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-3 text-left transition-colors hover:bg-[var(--color-surface-raised)]"

function TaskBody({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <>
      <div className="grid h-8 w-8 shrink-0 place-items-center rounded-md bg-[var(--color-surface-raised)] text-[var(--color-text-primary)]">
        {icon}
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-[var(--color-text-primary)]">{title}</div>
        <div className="text-xs text-[var(--color-text-secondary)]">{description}</div>
      </div>
      <ChevronRight />
    </>
  )
}

export function WhileYouWaitCard() {
  const tasks: Task[] = [
    {
      title: "Connect Slack",
      description: "Get scan results in #security.",
      icon: <SlackIcon />,
      href: "/integrations",
    },
    {
      title: "Wire up Jira write-back",
      description: "Create tickets for blockers automatically.",
      icon: <JiraIcon />,
      href: "/integrations",
    },
    {
      title: "Invite your team",
      description: "Add reviewers and owners.",
      icon: <TeamIcon />,
      href: "/settings/users",
    },
    {
      title: "60-second tour",
      description: "See how Aegis surfaces blockers.",
      icon: <TourIcon />,
      href: SUPPORT_URL,
    },
  ]

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
        <div className="mb-4">
          <h3 className="text-base font-semibold text-[var(--color-text-primary)]">While you wait</h3>
          <p className="text-xs text-[var(--color-text-tertiary)]">Get more out of your first scan</p>
        </div>
        <div className="flex flex-col gap-2">
          {tasks.map((task) =>
            task.href.startsWith("http") ? (
              <a key={task.title} href={task.href} target="_blank" rel="noopener noreferrer" className={TASK_ROW_CLASSES}>
                <TaskBody icon={task.icon} title={task.title} description={task.description} />
              </a>
            ) : (
              <Link key={task.title} href={task.href} className={TASK_ROW_CLASSES}>
                <TaskBody icon={task.icon} title={task.title} description={task.description} />
              </Link>
            ),
          )}
        </div>
      </div>
      <p className="text-center text-2xs text-[var(--color-text-tertiary)]">
        Need help?{" "}
        <a
          href={SUPPORT_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="text-[var(--color-text-secondary)] underline-offset-2 hover:underline"
        >
          Visit support
        </a>
      </p>
    </div>
  )
}
