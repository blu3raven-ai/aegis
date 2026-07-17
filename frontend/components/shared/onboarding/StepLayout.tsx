"use client"

import { Button } from "@/components/ui/Button"

interface StepLayoutProps {
  title: string
  description: string
  children: React.ReactNode
  onBack?: () => void
  onNext?: () => void
  onSkip?: () => void
  nextLabel?: string
  nextDisabled?: boolean
  isFirstStep?: boolean
  isLastStep?: boolean
  loading?: boolean
}

export function StepLayout({
  title,
  description,
  children,
  onBack,
  onNext,
  onSkip,
  nextLabel = "Next",
  nextDisabled = false,
  isFirstStep = false,
  isLastStep = false,
  loading = false,
}: StepLayoutProps) {
  return (
    <div className="flex flex-col gap-6">
      {/* Step header */}
      <div>
        <h2 className="text-xl font-semibold text-[var(--color-text-primary)]">{title}</h2>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">{description}</p>
      </div>

      {/* Body */}
      <div className="min-h-[200px]">{children}</div>

      {/* Navigation */}
      <div className="flex items-center justify-between border-t border-[var(--color-border)] pt-4">
        <div>
          {!isFirstStep && onBack && (
            <Button variant="secondary" size="md" onClick={onBack} disabled={loading}>
              Back
            </Button>
          )}
        </div>
        <div className="flex items-center gap-3">
          {onSkip && !isLastStep && (
            <Button variant="ghost" size="md" onClick={onSkip} disabled={loading}>
              Skip for now
            </Button>
          )}
          {onNext && (
            <Button
              variant="primary"
              size="md"
              onClick={onNext}
              disabled={nextDisabled}
              isLoading={loading}
            >
              {loading ? "Saving…" : nextLabel}
            </Button>
          )}
        </div>
      </div>
    </div>
  )
}
