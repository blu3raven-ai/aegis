"use client"

import Link from "next/link"
import { useCallback, useEffect, useState } from "react"
import { getSetupChecklist, type SetupTask } from "@/lib/client/setup-checklist"
import { cn } from "@/lib/shared/utils"

// Self-contained onboarding checklist. Lives on the home page in the empty
// state (no sources yet) and inline between dashboard sections once data
// arrives. Self-hides at 100% completion; /#setup deep-link scrolls here.

const STEP_ICON: Record<SetupTask["id"], string> = {
  connect_source:
    "M13.19 8.688a4.5 4.5 0 0 1 1.242 7.244l-4.5 4.5a4.5 4.5 0 0 1-6.364-6.364l1.757-1.757m9.86-2.54a4.5 4.5 0 0 0-1.242-7.244l4.5-4.5a4.5 4.5 0 1 0-6.364 6.364L10.5 8.121",
  deploy_runner:
    "M5.25 14.25h13.5m-13.5 0a3 3 0 0 1-3-3m3 3a3 3 0 1 0 0 6h13.5a3 3 0 1 0 0-6m-16.5-3a3 3 0 0 1 3-3h13.5a3 3 0 0 1 3 3m-19.5 0a4.5 4.5 0 0 1 .9-2.7L5.737 5.1a3.375 3.375 0 0 1 2.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 0 1 .9 2.7m0 0a3 3 0 0 1-3 3m0 3h.008v.008h-.008v-.008Zm0-6h.008v.008h-.008v-.008Zm-3 6h.008v.008h-.008v-.008Zm0-6h.008v.008h-.008v-.008Z",
  run_first_scan:
    "M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.347a1.125 1.125 0 0 1 0 1.972l-11.54 6.347a1.125 1.125 0 0 1-1.667-.986V5.653Z",
  configure_llm:
    "M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z",
  triage_finding:
    "M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
  set_sla_policy:
    "M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z",
  add_notification:
    "M14.857 17.082a23.848 23.848 0 0 0 5.454-1.31A8.967 8.967 0 0 1 18 9.75V9A6 6 0 0 0 6 9v.75a8.967 8.967 0 0 1-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 0 1-5.714 0m5.714 0a3 3 0 1 1-5.714 0",
}

export function SetupChecklistCard() {
  const [tasks, setTasks] = useState<SetupTask[] | null>(null)

  const load = useCallback(() => {
    void getSetupChecklist().then(setTasks).catch(() => setTasks(null))
  }, [])

  useEffect(() => { load() }, [load])

  // Refresh when the user returns from a setup page (e.g. just added a destination).
  useEffect(() => {
    function onFocus() { load() }
    window.addEventListener("focus", onFocus)
    return () => window.removeEventListener("focus", onFocus)
  }, [load])

  // /#setup deep-link — scroll into view once tasks are loaded.
  useEffect(() => {
    if (tasks === null || typeof window === "undefined") return
    if (window.location.hash !== "#setup") return
    document.getElementById("setup")?.scrollIntoView({ behavior: "smooth", block: "start" })
  }, [tasks])

  if (tasks === null) return null

  const completed = tasks.filter(t => t.done).length
  const total = tasks.length
  if (completed === total) return null

  const activeIndex = tasks.findIndex(t => !t.done)
  const progressPct = Math.round((completed / total) * 100)

  return (
    <section id="setup" aria-labelledby="setup-heading" className="scroll-mt-20">
      {/* Header row + progress bar */}
      <div className="mb-4">
        <div className="flex items-center justify-between gap-3">
          <h2
            id="setup-heading"
            className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"
          >
            Get started
          </h2>
          <span className="text-2xs font-medium tabular-nums text-[var(--color-text-tertiary)]">
            {completed} / {total} complete
          </span>
        </div>
        <div
          role="progressbar"
          aria-valuenow={completed}
          aria-valuemin={0}
          aria-valuemax={total}
          aria-label={`Setup: ${completed} of ${total} steps complete`}
          className="mt-2 h-1 w-full overflow-hidden rounded-full bg-[var(--color-border)]"
        >
          <div
            className="h-full rounded-full bg-[var(--color-accent)] transition-[width] duration-500 ease-out"
            style={{ width: `${progressPct}%` }}
          />
        </div>
      </div>

      {/* Steps card */}
      <div className="overflow-hidden rounded-md border border-[var(--color-border)] bg-[var(--color-surface)]">
        {tasks.map((task, i) => {
          const isDone = task.done
          const isActive = i === activeIndex
          const isUpcoming = !isDone && !isActive
          const iconPath = STEP_ICON[task.id]

          return (
            <div key={task.id}>
              {i > 0 && (
                <div className="mx-5 h-px bg-[var(--color-border-divider)]" />
              )}
              <Link
                href={task.href}
                aria-disabled={isDone || undefined}
                aria-current={isActive ? "step" : undefined}
                className={cn(
                  "group relative flex items-start gap-4 px-5 py-4 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-inset",
                  isDone && "pointer-events-none cursor-default",
                  isActive && "bg-[var(--color-accent)]/[0.04] hover:bg-[var(--color-accent)]/[0.07]",
                  isUpcoming && "hover:bg-[var(--color-bg-hover)]",
                )}
              >
                {/* Left accent rail on the active step */}
                {isActive && (
                  <span
                    aria-hidden="true"
                    className="absolute inset-y-0 left-0 w-[3px] rounded-r-full bg-[var(--color-accent)]"
                  />
                )}

                {/* Icon badge */}
                <span
                  aria-hidden="true"
                  className={cn(
                    "mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl transition-colors",
                    isDone && "bg-[var(--color-status-ok)]/10 text-[var(--color-status-ok-text)]",
                    isActive && "bg-[var(--color-accent)]/10 text-[var(--color-accent)]",
                    isUpcoming && "bg-[var(--color-surface-raised)] text-[var(--color-text-tertiary)]",
                  )}
                >
                  {isDone ? (
                    // Checkmark
                    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d={iconPath} />
                    </svg>
                  )}
                </span>

                {/* Text content */}
                <div className="min-w-0 flex-1 pt-1">
                  <p
                    className={cn(
                      "text-sm font-medium leading-snug",
                      isDone && "text-[var(--color-text-tertiary)] line-through decoration-[var(--color-text-tertiary)]/40",
                      isActive && "text-[var(--color-text-primary)]",
                      isUpcoming && "text-[var(--color-text-secondary)]",
                    )}
                  >
                    {task.title}
                  </p>
                  {!isDone && (
                    <p className="mt-0.5 text-xs leading-relaxed text-[var(--color-text-secondary)]">
                      {task.description}
                    </p>
                  )}
                </div>

                {/* CTA */}
                {isActive && (
                  <span
                    aria-hidden="true"
                    className="mt-1 inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-semibold text-white transition-colors group-hover:bg-[var(--color-accent-hover)]"
                  >
                    Start
                    <svg className="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3" />
                    </svg>
                  </span>
                )}
                {isUpcoming && (
                  <span
                    aria-hidden="true"
                    className="mt-1.5 shrink-0 text-[var(--color-text-tertiary)] transition-transform group-hover:translate-x-0.5"
                  >
                    <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                      <path d="M9 18l6-6-6-6" />
                    </svg>
                  </span>
                )}
              </Link>
            </div>
          )
        })}
      </div>
    </section>
  )
}
