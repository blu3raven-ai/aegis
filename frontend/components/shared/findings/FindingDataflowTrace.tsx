"use client"

import { useState } from "react"

export interface DataflowStep {
  file: string
  line: number
  snippet: string
  role: "source" | "intermediate" | "sink"
}

interface FindingDataflowTraceProps {
  trace: DataflowStep[] | null | undefined
  defaultExpanded?: boolean
}

/**
 * Source-to-sink trace for taint findings. Renders nothing when the trace
 * is absent.
 */
export function FindingDataflowTrace({
  trace,
  defaultExpanded = false,
}: FindingDataflowTraceProps) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  if (!trace || trace.length === 0) return null

  return (
    <section className="border-t border-[var(--color-border)] pt-3 mt-3">
      <button
        type="button"
        onClick={() => setExpanded(v => !v)}
        className="flex items-center gap-2 text-sm font-semibold text-[var(--color-text-primary)]"
        aria-expanded={expanded}
      >
        <span aria-hidden="true">{expanded ? "▼" : "▶"}</span>
        <span>
          Dataflow trace · {trace.length} step{trace.length === 1 ? "" : "s"}
        </span>
      </button>
      {expanded && (
        <ol className="mt-2 space-y-2">
          {trace.map((step, i) => (
            <li
              key={i}
              className="rounded border border-[var(--color-border)] p-2"
            >
              <div className="flex items-center gap-2 text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                <span className="rounded-full bg-[var(--color-surface)] px-1.5 py-0.5">
                  {i + 1}
                </span>
                <span>{step.role}</span>
                <span className="font-mono">·</span>
                <span className="font-mono">
                  {step.file}:{step.line}
                </span>
              </div>
              <pre className="mt-1 overflow-x-auto font-mono text-xs text-[var(--color-text-primary)]">
                {step.snippet}
              </pre>
            </li>
          ))}
        </ol>
      )}
    </section>
  )
}
