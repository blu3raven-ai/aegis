"use client"

import { useState } from "react"
import { DestinationForm } from "@/components/shared/notifications/DestinationForm"
import type { CreateDestinationPayload } from "@/lib/client/destinations-api"
import { createDestination } from "@/lib/client/destinations-api"
import { StepLayout } from "@/components/shared/onboarding/StepLayout"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

interface AlertsStepProps {
  onNext: (data: { destination_id?: number }) => void
  onBack: () => void
  onSkip: () => void
}

export function AlertsStep({ onNext, onBack, onSkip }: AlertsStepProps) {
  const [submitting, setSubmitting] = useState(false)
  const [saved, setSaved] = useState<{ id: number; name: string } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)

  async function handleSubmit(payload: CreateDestinationPayload | (Record<string, unknown> & { id: number })) {
    setSubmitting(true)
    setError(null)
    try {
      const dest = await createDestination(payload as CreateDestinationPayload)
      setSaved({ id: dest.id, name: dest.name })
      setShowForm(false)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to save destination.")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <StepLayout
      title="Configure alerts"
      description="Send critical findings to a Slack channel or email address so your team is notified immediately."
      onBack={onBack}
      onNext={() => onNext(saved ? { destination_id: saved.id } : {})}
      onSkip={onSkip}
      nextLabel="Continue"
    >
      <div className="flex flex-col gap-4">
        {saved && !showForm && (
          <div className="flex items-center justify-between rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4">
            <div className="flex items-center gap-3">
              <svg className="h-5 w-5 text-emerald-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
              </svg>
              <span className="text-sm font-medium text-[var(--color-text-primary)]">
                Destination <strong>{saved.name}</strong> saved.
              </span>
            </div>
            <button
              type="button"
              onClick={() => setShowForm(true)}
              className="text-xs text-[var(--color-accent)] hover:underline"
            >
              Change
            </button>
          </div>
        )}

        {!saved && !showForm && (
          <div className="flex flex-col items-start gap-4 rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-surface)] p-6">
            <p className="text-sm text-[var(--color-text-secondary)]">
              No alert destination configured yet. Add a Slack webhook or email address to receive notifications for critical findings.
            </p>
            <button
              type="button"
              onClick={() => setShowForm(true)}
              className="rounded-lg border border-[var(--color-accent)] px-4 py-2 text-sm text-[var(--color-accent)] transition-colors hover:bg-[var(--color-accent-subtle)]"
            >
              Add destination
            </button>
          </div>
        )}

        {showForm && (
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
            {error && (
              <p className="mb-3 text-xs text-[var(--color-severity-high)]">{error}</p>
            )}
            <DestinationForm
              initial={null}
              orgId={ORG_ID}
              onSubmit={handleSubmit}
              onCancel={() => setShowForm(false)}
              submitting={submitting}
            />
          </div>
        )}
      </div>
    </StepLayout>
  )
}
