"use client"

import Link from "next/link"
import { useCallback, useEffect, useState } from "react"
import {
  getSetupChecklist,
  type SetupTask,
} from "@/lib/client/setup-checklist"
import { cn } from "@/lib/shared/utils"

// Inline dashboard card. Lives on the home page between "Just introduced" and
// "Open in your repos", matching the surrounding card chrome so it reads as
// part of the dashboard instead of as a floating overlay. Linear / Vercel
// pattern (vs Stripe's floating widget — replaced because it competed with
// the chat-widget zone and felt third-party).
//
// Cards self-hide once every task is complete; the HelpButton's "Resume
// setup" menu entry deep-links here via /#setup.

const TASK_CTA: Record<SetupTask["id"], string> = {
  connect_source: "Connect",
  run_first_scan: "Run",
  triage_finding: "Open",
  set_sla_policy: "Set",
  add_notification: "Add",
}

export function SetupChecklistCard() {
  const [tasks, setTasks] = useState<SetupTask[] | null>(null)

  const load = useCallback(() => {
    void getSetupChecklist().then(setTasks).catch(() => setTasks(null))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  // Refresh when the user comes back from a deep-linked page (e.g. they
  // just configured a notification destination and tabbed back).
  useEffect(() => {
    function onFocus() { load() }
    window.addEventListener("focus", onFocus)
    return () => window.removeEventListener("focus", onFocus)
  }, [load])

  // If the user lands on `/#setup`, scroll the card into view once it's mounted.
  // useLayoutEffect would be sharper but `tasks` arrives async — wait for it.
  useEffect(() => {
    if (tasks === null) return
    if (typeof window === "undefined") return
    if (window.location.hash !== "#setup") return
    const el = document.getElementById("setup")
    el?.scrollIntoView({ behavior: "smooth", block: "start" })
  }, [tasks])

  if (tasks === null) return null

  const completed = tasks.filter((t) => t.done).length
  const total = tasks.length

  // Self-hide at 100%; HelpButton hides its own entry too so users don't
  // bounce to a missing card.
  if (completed === total) return null

  return (
    <section
      id="setup"
      aria-labelledby="setup-checklist-heading"
      // Account for any sticky header when the hash scrolls us here.
      className="scroll-mt-20"
    >
      <div className="mb-3 flex items-baseline justify-between gap-3">
        <h2
          id="setup-checklist-heading"
          className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-secondary)]"
        >
          Get started
        </h2>
        <span className="text-xs tabular-nums text-[var(--color-text-tertiary)]">
          {completed} of {total} complete
        </span>
      </div>

      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)]">
        <ul className="divide-y divide-[var(--color-border-divider)]">
          {tasks.map((task) => {
            const cta = TASK_CTA[task.id]
            return (
              <li key={task.id}>
                <Link
                  href={task.href}
                  aria-disabled={task.done || undefined}
                  className={cn(
                    "group flex items-center gap-4 px-5 py-4 transition-colors",
                    task.done
                      ? "cursor-default pointer-events-none"
                      : "hover:bg-[var(--color-bg-hover)]",
                  )}
                >
                  <span
                    aria-hidden="true"
                    className={cn(
                      "flex h-5 w-5 shrink-0 items-center justify-center rounded-full border transition-colors",
                      task.done
                        ? "border-[var(--color-status-ok)] bg-[var(--color-status-ok)] text-[var(--color-accent-on)]"
                        : "border-[var(--color-border-strong)] bg-[var(--color-surface)]",
                    )}
                  >
                    {task.done && (
                      <svg
                        viewBox="0 0 16 16"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth={3}
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        className="h-3 w-3"
                      >
                        <path d="m3.5 8 3 3 6-6" />
                      </svg>
                    )}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p
                      className={cn(
                        "text-sm font-medium",
                        task.done
                          ? "text-[var(--color-text-tertiary)] line-through"
                          : "text-[var(--color-text-primary)]",
                      )}
                    >
                      {task.title}
                    </p>
                    {!task.done && (
                      <p className="mt-0.5 text-xs leading-relaxed text-[var(--color-text-secondary)]">
                        {task.description}
                      </p>
                    )}
                  </div>
                  {!task.done && (
                    <span
                      aria-hidden="true"
                      className="ml-auto inline-flex items-center gap-1 text-xs font-semibold text-[var(--color-accent)] transition-transform group-hover:translate-x-0.5"
                    >
                      {cta}
                      <svg
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth={2}
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        className="h-3.5 w-3.5"
                      >
                        <path d="M9 6l6 6-6 6" />
                      </svg>
                    </span>
                  )}
                </Link>
              </li>
            )
          })}
        </ul>
      </div>
    </section>
  )
}
