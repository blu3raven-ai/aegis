"use client"

const STEP_LABELS = ["Welcome", "Connect", "Scan", "Alerts", "Policy"] as const

interface StepIndicatorProps {
  currentStep: number // 0-indexed
  completedSteps: Set<number>
}

export function StepIndicator({ currentStep, completedSteps }: StepIndicatorProps) {
  return (
    <div className="flex items-center justify-center gap-0 overflow-x-auto pb-1">
      {STEP_LABELS.map((label, idx) => {
        const done = completedSteps.has(idx)
        const active = idx === currentStep

        return (
          <div key={idx} className="flex items-center">
            {/* Node */}
            <div className="flex flex-col items-center gap-1.5">
              <div
                className={`flex h-8 w-8 items-center justify-center rounded-full border-2 text-xs font-semibold transition-colors ${
                  done
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)] text-white"
                    : active
                    ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                    : "border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)]"
                }`}
              >
                {done ? (
                  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
                    <path d="M4.5 12.75l6 6 9-13.5" />
                  </svg>
                ) : (
                  <span>{idx + 1}</span>
                )}
              </div>
              <span
                className={`whitespace-nowrap text-2xs font-medium ${
                  active
                    ? "text-[var(--color-text-primary)]"
                    : "text-[var(--color-text-secondary)]"
                }`}
              >
                {label}
              </span>
            </div>

            {/* Connector line — not after last item */}
            {idx < STEP_LABELS.length - 1 && (
              <div
                className={`mx-1 mb-5 h-0.5 w-10 shrink-0 transition-colors sm:w-16 ${
                  completedSteps.has(idx)
                    ? "bg-[var(--color-accent)]"
                    : "bg-[var(--color-border)]"
                }`}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}
