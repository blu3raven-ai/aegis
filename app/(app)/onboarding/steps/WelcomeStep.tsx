"use client"

import { StepLayout } from "@/components/shared/onboarding/StepLayout"

interface WelcomeStepProps {
  onNext: () => void
}

const FEATURES = [
  { icon: "M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z", label: "Dependency vulnerability scanning (SCA)" },
  { icon: "M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z", label: "Secret detection across git history" },
  { icon: "M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5", label: "SAST code scanning with AI review" },
  { icon: "M4 6l8 12 8-12M4 18h16", label: "Attack chain correlation and risk scoring" },
]

export function WelcomeStep({ onNext }: WelcomeStepProps) {
  return (
    <StepLayout
      title="Welcome to Aegis"
      description="Let's get your organisation set up in a few quick steps."
      onNext={onNext}
      nextLabel="Get started"
      isFirstStep
    >
      <div className="grid gap-3 sm:grid-cols-2">
        {FEATURES.map((f) => (
          <div
            key={f.label}
            className="flex items-start gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4"
          >
            <svg
              className="mt-0.5 h-5 w-5 shrink-0 text-[var(--color-accent)]"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={1.5}
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d={f.icon} />
            </svg>
            <span className="text-sm text-[var(--color-text-primary)]">{f.label}</span>
          </div>
        ))}
      </div>
    </StepLayout>
  )
}
