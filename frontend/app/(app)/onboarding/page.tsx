"use client"

import { useState, useEffect, useCallback } from "react"
import { StepIndicator } from "@/components/shared/onboarding/StepIndicator"
import { CompletionCelebration } from "@/components/shared/onboarding/CompletionCelebration"
import { SignInStep, type SignInProvider } from "./steps/SignInStep"
import { ConnectSourceStep } from "./steps/ConnectSourceStep"
import { PickReposStep } from "./steps/PickReposStep"
import { SmokeTestStep } from "./steps/SmokeTestStep"
import {
  getOnboardingState,
  completeStep,
  skipStep,
  dismissOnboarding,
  type OnboardingState,
  type StepId,
} from "@/lib/client/onboarding-api"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"
const STEPS: StepId[] = ["connect_source", "pick_repos", "smoke_test"]

export default function OnboardingPage() {
  const [signedIn, setSignedIn] = useState(false)
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

  const completedSteps = new Set<number>()
  if (signedIn) completedSteps.add(0)
  STEPS.forEach((id, idx) => {
    if (state?.steps[id].completed) completedSteps.add(idx + 1)
  })

  const indicatorStep = signedIn ? currentStep + 1 : 0

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
      const updated = await completeStep(ORG_ID, stepId, data)
      setState(updated)
      await dismissOnboarding(ORG_ID, stepId)
      setDone(true)
    } finally {
      setSaving(false)
    }
  }

  async function handleSkipAndDismiss(stepId: StepId) {
    setSaving(true)
    try {
      const updated = await skipStep(ORG_ID, stepId)
      setState(updated)
      await dismissOnboarding(ORG_ID, stepId)
      setDone(true)
    } finally {
      setSaving(false)
    }
  }

  const advance = () => setCurrentStep((s) => Math.min(s + 1, STEPS.length - 1))
  const retreat = () => setCurrentStep((s) => Math.max(s - 1, 0))

  const handleProviderClick = (provider: SignInProvider) => {
    console.log("[onboarding] sso provider clicked", provider)
    setSignedIn(true)
  }

  const handleMagicLinkRequest = (email: string) => {
    console.log("[onboarding] magic link requested", email)
    setSignedIn(true)
  }

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

  const showSignIn = !signedIn
  const containerMaxWidth = showSignIn ? "max-w-4xl" : "max-w-2xl"

  return (
    <div className={`mx-auto ${containerMaxWidth} px-4 py-10`}>
      <div className="mb-8 flex flex-col gap-2 text-center">
        <h1 className="text-3xl font-bold text-[var(--color-text-primary)]">Set up Aegis</h1>
        <p className="text-sm text-[var(--color-text-secondary)]">
          Complete these steps to get the most out of your security portal.
        </p>
      </div>

      <div className="mb-10">
        <StepIndicator currentStep={indicatorStep} completedSteps={completedSteps} />
      </div>

      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-sm">
        {showSignIn && (
          <SignInStep
            onProviderClick={handleProviderClick}
            onMagicLinkRequest={handleMagicLinkRequest}
          />
        )}
        {!showSignIn && currentStep === 0 && (
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
        {!showSignIn && currentStep === 1 && (
          <PickReposStep
            onNext={async (data) => {
              await handleComplete("pick_repos", data)
              advance()
            }}
            onBack={retreat}
            onSkip={async () => {
              await handleSkip("pick_repos")
              advance()
            }}
          />
        )}
        {!showSignIn && currentStep === 2 && (
          <SmokeTestStep
            onNext={async (data) => {
              await handleDismiss("smoke_test", data)
            }}
            onBack={retreat}
            onSkip={async () => {
              await handleSkipAndDismiss("smoke_test")
            }}
          />
        )}
      </div>

      {saving && (
        <p className="mt-3 text-center text-xs text-[var(--color-text-secondary)]">Saving…</p>
      )}
    </div>
  )
}
