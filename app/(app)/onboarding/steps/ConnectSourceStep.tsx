"use client"

import { useState } from "react"
import { StepLayout } from "@/components/shared/onboarding/StepLayout"

type Provider = "github" | "gitlab" | "bitbucket"

const PROVIDERS: { id: Provider; label: string; iconPath: string }[] = [
  {
    id: "github",
    label: "GitHub",
    iconPath: "M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2Z",
  },
  {
    id: "gitlab",
    label: "GitLab",
    iconPath: "M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 0 1-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 0 1 4.82 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0 1 18.6 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.51 1.22 3.78a.84.84 0 0 1-.3.92Z",
  },
  {
    id: "bitbucket",
    label: "Bitbucket",
    iconPath: "M.778 1.213a.768.768 0 0 0-.768.892l3.263 19.81c.084.5.52.865 1.025.865h15.004c.379 0 .7-.26.78-.633L23.222 2.1a.768.768 0 0 0-.768-.892L.778 1.213zM14.52 15.53H9.522L8.17 8.466h7.561l-1.211 7.064z",
  },
]

interface ConnectSourceStepProps {
  onNext: (data: { provider: Provider; configured: boolean }) => void
  onBack: () => void
  onSkip: () => void
}

export function ConnectSourceStep({ onNext, onBack, onSkip }: ConnectSourceStepProps) {
  const [selected, setSelected] = useState<Provider | null>(null)

  return (
    <StepLayout
      title="Connect a source"
      description="Link your GitHub, GitLab, or Bitbucket organisation so Aegis can discover repositories."
      onBack={onBack}
      onNext={selected ? () => onNext({ provider: selected, configured: true }) : undefined}
      onSkip={onSkip}
      nextLabel="Continue"
      nextDisabled={!selected}
    >
      <div className="flex flex-col gap-4">
        <div className="grid gap-3 sm:grid-cols-3">
          {PROVIDERS.map((p) => (
            <button
              key={p.id}
              type="button"
              onClick={() => setSelected(p.id)}
              className={`flex flex-col items-center gap-3 rounded-xl border-2 p-6 transition-colors ${
                selected === p.id
                  ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)]"
                  : "border-[var(--color-border)] bg-[var(--color-surface)] hover:border-[var(--color-accent)]/50"
              }`}
            >
              <svg className="h-8 w-8 text-[var(--color-text-primary)]" viewBox="0 0 24 24" fill="currentColor">
                <path d={p.iconPath} />
              </svg>
              <span className="text-sm font-medium text-[var(--color-text-primary)]">{p.label}</span>
            </button>
          ))}
        </div>

        {selected && (
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4">
            <p className="text-sm text-[var(--color-text-secondary)]">
              Full connection configuration is available in{" "}
              <a
                href="/settings/sources"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[var(--color-accent)] underline-offset-2 hover:underline"
              >
                Settings › Sources
              </a>
              . Click <strong>Continue</strong> to proceed — you can configure the webhook and token there.
            </p>
          </div>
        )}
      </div>
    </StepLayout>
  )
}
