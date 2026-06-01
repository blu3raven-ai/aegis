"use client"

import { useState, useEffect, useCallback } from "react"
import { StepIndicator } from "@/components/shared/onboarding/StepIndicator"
import { CompletionCelebration } from "@/components/shared/onboarding/CompletionCelebration"
import { WelcomeStep } from "./steps/WelcomeStep"
import { ConnectSourceStep } from "./steps/ConnectSourceStep"
import { SmokeTestStep } from "./steps/SmokeTestStep"
import { AlertsStep } from "./steps/AlertsStep"
import { PolicyStep } from "./steps/PolicyStep"
import {
  getOnboardingState,
  completeStep,
  skipStep,
  dismissOnboarding,
  type OnboardingState,
  type StepId,
} from "@/lib/client/onboarding-api"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"
const STEPS: StepId[] = ["welcome", "connect_source", "smoke_test", "alerts", "policy"]

export default function OnboardingPage() {
  const [currentStep, setCurrentStep] = useState(0)
  const [state, setState] = useState<OnboardingState | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [done, setDone] = useState(false)

  const loadState = useCallback(async () => {
    try {
      const s = await getOnboardingState(ORG_ID)
      setState(s)
      if (s.dismissed) {
        setDone(true)
      } else {
        // Resume at first incomplete step
        const firstIncomplete = STEPS.findIndex((id) => !s.steps[id].completed && !s.steps[id].skipped)
        setCurrentStep(firstIncomplete >= 0 ? firstIncomplete : STEPS.length - 1)
      }
    } catch {
      // Fallback: start from beginning
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadState()
  }, [loadState])

  const completedSteps = new Set<number>(
    STEPS.map((id, idx) => (state?.steps[id].completed ? idx : -1)).filter((i) => i >= 0)
  )

  async function handleComplete(stepId: StepId, data: Record<string, unknown>) {
    setSaving(true)
    try {
      const updated = await completeStep(ORG_ID, stepId, data)
      setState(updated)
    } finally {
      setSaving(false)
    }
  }

  async function handleSkip(stepId: StepId) {
    setSaving(true)
    try {
      const updated = await skipStep(ORG_ID, stepId)
      setState(updated)
    } finally {
      setSaving(false)
    }
  }

  async function handleDismiss(stepId: StepId, data: Record<string, unknown>) {
    setSaving(true)
    try {
      await handleComplete(stepId, data)
      await dismissOnboarding(ORG_ID)
      setDone(true)
    } finally {
      setSaving(false)
    }
  }

  const advance = () => setCurrentStep((s) => Math.min(s + 1, STEPS.length - 1))
  const retreat = () => setCurrentStep((s) => Math.max(s - 1, 0))

  if (loading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--color-border)] border-t-[var(--color-accent)]" />
      </div>
    )
  }

  if (done) {
    return (
      <div className="mx-auto max-w-2xl px-4 py-16">
        <CompletionCelebration />
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-2xl px-4 py-10">
      {/* Header */}
      <div className="mb-8 flex flex-col gap-2 text-center">
        <h1 className="text-3xl font-bold text-[var(--color-text-primary)]">Set up Aegis</h1>
        <p className="text-sm text-[var(--color-text-secondary)]">
          Complete these steps to get the most out of your security portal.
        </p>
      </div>

      {/* Step indicator */}
      <div className="mb-10">
        <StepIndicator currentStep={currentStep} completedSteps={completedSteps} />
      </div>

      {/* Step content */}
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-sm">
        {currentStep === 0 && (
          <WelcomeStep
            onNext={async () => {
              await handleComplete("welcome", {})
              advance()
            }}
          />
        )}
        {currentStep === 1 && (
          <ConnectSourceStep
            onNext={async (data) => {
              await handleComplete("connect_source", data)
              advance()
            }}
            onBack={retreat}
            onSkip={async () => {
              await handleSkip("connect_source")
              advance()
            }}
          />
        )}
        {currentStep === 2 && (
          <SmokeTestStep
            onNext={async (data) => {
              await handleComplete("smoke_test", data)
              advance()
            }}
            onBack={retreat}
            onSkip={async () => {
              await handleSkip("smoke_test")
              advance()
            }}
          />
        )}
        {currentStep === 3 && (
          <AlertsStep
            onNext={async (data) => {
              await handleComplete("alerts", data)
              advance()
            }}
            onBack={retreat}
            onSkip={async () => {
              await handleSkip("alerts")
              advance()
            }}
          />
        )}
        {currentStep === 4 && (
          <PolicyStep
            onNext={async (data) => {
              await handleDismiss("policy", data)
            }}
            onBack={retreat}
          />
        )}
      </div>

      {/* Saving indicator */}
      {saving && (
        <p className="mt-3 text-center text-xs text-[var(--color-text-secondary)]">Saving…</p>
      )}
    </div>
  )
}
