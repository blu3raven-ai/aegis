"use client"

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
            <button
              type="button"
              onClick={onBack}
              disabled={loading}
              className="rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)] disabled:opacity-50"
            >
              Back
            </button>
          )}
        </div>
        <div className="flex items-center gap-3">
          {onSkip && !isLastStep && (
            <button
              type="button"
              onClick={onSkip}
              disabled={loading}
              className="text-sm text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)] disabled:opacity-50"
            >
              Skip for now
            </button>
          )}
          {onNext && (
            <button
              type="button"
              onClick={onNext}
              disabled={nextDisabled || loading}
              className="rounded-lg bg-[var(--color-accent)] px-5 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? "Saving…" : nextLabel}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
