"use client"

type Provider = "github" | "gitlab" | "bitbucket"

interface PermissionItem {
  label: string
  granted: boolean
}

interface ProviderPermissions {
  items: PermissionItem[]
  note?: string
}

const PERMISSIONS: Record<Provider, ProviderPermissions> = {
  github: {
    items: [
      { label: "Read code", granted: true },
      { label: "Repo contents on push", granted: true },
      { label: "No write access", granted: false },
      { label: "No PR access", granted: false },
    ],
    note: "We only read source for scanning. We never push commits or open PRs unless you opt in.",
  },
  gitlab: {
    items: [
      { label: "Read repository", granted: true },
      { label: "Read pipeline status", granted: true },
      { label: "No write access", granted: false },
    ],
  },
  bitbucket: {
    items: [
      { label: "Read repository", granted: true },
      { label: "Read project members", granted: true },
      { label: "No write access", granted: false },
    ],
  },
}

const PROVIDER_LABEL: Record<Provider, string> = {
  github: "GitHub",
  gitlab: "GitLab",
  bitbucket: "Bitbucket",
}

interface PermissionPreviewCardProps {
  provider: Provider | null
}

export function PermissionPreviewCard({ provider }: PermissionPreviewCardProps) {
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="flex items-start gap-3">
        <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-[var(--color-accent)]/10 text-[var(--color-accent)]">
          <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
          </svg>
        </div>
        <div className="min-w-0">
          <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
            Permissions preview
          </h3>
          <p className="text-2xs text-[var(--color-text-tertiary)]">
            {provider ? `Aegis will request access to ${PROVIDER_LABEL[provider]}` : "Read-only by default"}
          </p>
        </div>
      </div>

      {provider ? (
        <div className="mt-4 flex flex-col gap-2">
          {PERMISSIONS[provider].items.map((item) => (
            <div key={item.label} className="flex items-start gap-2.5">
              {item.granted ? (
                <svg
                  className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2.5}
                  aria-hidden="true"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 12l5 5L20 7" />
                </svg>
              ) : (
                <svg
                  className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--color-text-tertiary)]"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2}
                  aria-hidden="true"
                >
                  <circle cx="12" cy="12" r="9" />
                  <path strokeLinecap="round" d="M5.636 5.636l12.728 12.728" />
                </svg>
              )}
              <span
                className={`text-xs ${
                  item.granted
                    ? "text-[var(--color-text-secondary)]"
                    : "text-[var(--color-text-tertiary)]"
                }`}
              >
                {item.label}
              </span>
            </div>
          ))}
          {PERMISSIONS[provider].note && (
            <p className="mt-3 border-t border-[var(--color-border)] pt-3 text-2xs leading-relaxed text-[var(--color-text-tertiary)]">
              {PERMISSIONS[provider].note}
            </p>
          )}
        </div>
      ) : (
        <p className="mt-4 text-xs text-[var(--color-text-tertiary)]">
          Select a source to see the permissions we&apos;ll request.
        </p>
      )}
    </div>
  )
}
