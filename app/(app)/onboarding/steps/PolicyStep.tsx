"use client"

import { useState } from "react"
import { StepLayout } from "@/components/shared/onboarding/StepLayout"

type PolicyOption = "block_on_critical" | "warn_on_high_plus" | "monitor_only"

const POLICIES: { id: PolicyOption; label: string; description: string; badge: string; badgeColor: string }[] = [
  {
    id: "block_on_critical",
    label: "Block on critical",
    description: "CI gates will fail and PRs blocked when critical vulnerabilities are detected.",
    badge: "Strict",
    badgeColor: "bg-red-500/10 text-red-500 border-red-500/30",
  },
  {
    id: "warn_on_high_plus",
    label: "Warn on high+",
    description: "High and critical findings generate warnings and notifications without blocking deployments.",
    badge: "Balanced",
    badgeColor: "bg-amber-500/10 text-amber-500 border-amber-500/30",
  },
  {
    id: "monitor_only",
    label: "Monitor only",
    description: "All findings are recorded and surfaced in the dashboard. No CI gates or blocks.",
    badge: "Permissive",
    badgeColor: "bg-[var(--color-accent)]/10 text-[var(--color-accent)] border-[var(--color-accent)]/30",
  },
]

interface PolicyStepProps {
  onNext: (data: { policy: PolicyOption }) => void
  onBack: () => void
}

export function PolicyStep({ onNext, onBack }: PolicyStepProps) {
  const [selected, setSelected] = useState<PolicyOption>("warn_on_high_plus")

  return (
    <StepLayout
      title="Choose a baseline policy"
      description="This sets the default enforcement posture. You can refine it later in Settings › Policies."
      onBack={onBack}
      onNext={() => onNext({ policy: selected })}
      nextLabel="Finish setup"
      isLastStep
    >
      <div className="flex flex-col gap-3">
        {POLICIES.map((p) => (
          <button
            key={p.id}
            type="button"
            onClick={() => setSelected(p.id)}
            className={`flex items-start gap-4 rounded-xl border-2 p-4 text-left transition-colors ${
              selected === p.id
                ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)]"
                : "border-[var(--color-border)] bg-[var(--color-surface)] hover:border-[var(--color-accent)]/50"
            }`}
          >
            {/* Radio indicator */}
            <div
              className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border-2 transition-colors ${
                selected === p.id
                  ? "border-[var(--color-accent)] bg-[var(--color-accent)]"
                  : "border-[var(--color-border)]"
              }`}
            >
              {selected === p.id && <div className="h-2 w-2 rounded-full bg-white" />}
            </div>

            <div className="flex flex-1 flex-col gap-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-[var(--color-text-primary)]">{p.label}</span>
                <span className={`rounded-full border px-2 py-px text-[10px] font-semibold ${p.badgeColor}`}>
                  {p.badge}
                </span>
              </div>
              <p className="text-sm text-[var(--color-text-secondary)]">{p.description}</p>
            </div>
          </button>
        ))}
      </div>
    </StepLayout>
  )
}
