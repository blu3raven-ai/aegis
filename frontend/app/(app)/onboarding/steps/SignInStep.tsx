"use client"

import { useState } from "react"

import { Button } from "@/components/ui/Button"

export type SignInProvider = "google" | "microsoft" | "github" | "okta" | "saml"

interface SignInStepProps {
  onProviderClick: (provider: SignInProvider) => void
  onMagicLinkRequest: (email: string) => void
}

interface ProviderConfig {
  id: SignInProvider
  label: string
  ariaLabel: string
  icon: React.ReactNode
}

const PROVIDERS: ProviderConfig[] = [
  {
    id: "google",
    label: "Continue with Google",
    ariaLabel: "Sign in with Google",
    icon: (
      <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true">
        <path
          fill="#4285F4"
          d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
        />
        <path
          fill="#34A853"
          d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84A10.99 10.99 0 0 0 12 23z"
        />
        <path
          fill="#FBBC05"
          d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18A10.99 10.99 0 0 0 1 12c0 1.78.43 3.46 1.18 4.93l2.85-2.22.81-.62z"
        />
        <path
          fill="#EA4335"
          d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
        />
      </svg>
    ),
  },
  {
    id: "microsoft",
    label: "Continue with Microsoft",
    ariaLabel: "Sign in with Microsoft",
    icon: (
      <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true">
        <path fill="#F25022" d="M1 1h10v10H1z" />
        <path fill="#7FBA00" d="M13 1h10v10H13z" />
        <path fill="#00A4EF" d="M1 13h10v10H1z" />
        <path fill="#FFB900" d="M13 13h10v10H13z" />
      </svg>
    ),
  },
  {
    id: "github",
    label: "Continue with GitHub",
    ariaLabel: "Sign in with GitHub",
    icon: (
      <svg
        viewBox="0 0 24 24"
        fill="currentColor"
        className="h-4 w-4 text-[var(--color-text-primary)]"
        aria-hidden="true"
      >
        <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
      </svg>
    ),
  },
  {
    id: "okta",
    label: "Continue with Okta",
    ariaLabel: "Sign in with Okta",
    icon: (
      <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true">
        <circle cx="12" cy="12" r="9" fill="none" stroke="#007DC1" strokeWidth="3" />
      </svg>
    ),
  },
  {
    id: "saml",
    label: "Continue with SAML SSO",
    ariaLabel: "Sign in with SAML single sign-on",
    icon: (
      <svg
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        className="h-4 w-4 text-[var(--color-accent)]"
        aria-hidden="true"
      >
        <path d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
      </svg>
    ),
  },
]

const ENTERPRISE_FEATURES = [
  "SAML 2.0 / OIDC",
  "SCIM provisioning",
  "Audit log streaming",
  "Customer-managed keys",
]

function CheckIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      className="h-3 w-3 shrink-0 text-[var(--color-success)]"
      aria-hidden="true"
    >
      <path d="M5 12l5 5L20 7" />
    </svg>
  )
}

function ShieldIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      className="h-3 w-3"
      aria-hidden="true"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  )
}

export function SignInStep({ onProviderClick, onMagicLinkRequest }: SignInStepProps) {
  const [email, setEmail] = useState("")

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!email) return
    onMagicLinkRequest(email)
  }

  return (
    <div className="grid grid-cols-1 gap-8 md:grid-cols-2">
      <div className="flex flex-col">
        <h2 className="text-base font-semibold text-[var(--color-text-primary)]">
          Sign in to Aegis
        </h2>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Use SSO or your work email to continue.
        </p>

        <div className="mt-6 flex flex-col gap-2">
          {PROVIDERS.map((provider) => (
            <button
              key={provider.id}
              type="button"
              aria-label={provider.ariaLabel}
              onClick={() => onProviderClick(provider.id)}
              className="flex items-center justify-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3 text-sm font-medium text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)]"
            >
              {provider.icon}
              <span>{provider.label}</span>
            </button>
          ))}
        </div>

        <div className="my-6 flex items-center gap-3">
          <div className="h-px flex-1 bg-[var(--color-border)]" />
          <span className="font-mono text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
            or continue with email
          </span>
          <div className="h-px flex-1 bg-[var(--color-border)]" />
        </div>

        <form className="flex flex-col gap-3" onSubmit={handleSubmit}>
          <label className="flex flex-col gap-1.5">
            <span className="text-xs font-semibold text-[var(--color-text-secondary)]">
              Work email
            </span>
            <input
              type="email"
              required
              autoComplete="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2.5 text-sm text-[var(--color-text-primary)] outline-none transition-colors placeholder:text-[var(--color-text-secondary)] focus:border-[var(--color-accent)]"
            />
          </label>
          <Button type="submit" variant="primary" size="md">
            Send magic link
          </Button>
        </form>

        <div className="mt-7 flex flex-col gap-3 border-t border-[var(--color-border)] pt-5">
          <div className="flex items-center justify-between text-xs">
            <span className="text-[var(--color-text-secondary)]">
              Don&apos;t have an account?
            </span>
            <a
              href="#"
              className="font-medium text-[var(--color-accent)] hover:underline"
            >
              Sign up
            </a>
          </div>
          <p className="text-2xs leading-relaxed text-[var(--color-text-secondary)]">
            By signing in, you agree to our{" "}
            <a href="#" className="underline hover:text-[var(--color-text-primary)]">
              Terms
            </a>{" "}
            and{" "}
            <a href="#" className="underline hover:text-[var(--color-text-primary)]">
              Privacy Policy
            </a>
            . SOC 2 Type II - GDPR.
          </p>
        </div>
      </div>

      <aside className="hidden md:block">
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-6">
          <div className="inline-flex items-center gap-1.5 rounded-full border border-[var(--color-border)] bg-[var(--color-accent-subtle)] px-2.5 py-1 font-mono text-2xs font-semibold uppercase tracking-[0.14em] text-[var(--color-accent)]">
            <ShieldIcon />
            Enterprise
          </div>
          <h3 className="mt-3 text-base font-semibold text-[var(--color-text-primary)]">
            Already have an SSO domain?
          </h3>
          <p className="mt-1 text-xs leading-relaxed text-[var(--color-text-secondary)]">
            Aegis auto-routes you to your org&apos;s identity provider once SSO is set up.
          </p>
          <ul className="mt-4 flex flex-col gap-2">
            {ENTERPRISE_FEATURES.map((feature) => (
              <li
                key={feature}
                className="flex items-start gap-2 text-xs text-[var(--color-text-secondary)]"
              >
                <span className="mt-0.5">
                  <CheckIcon />
                </span>
                <span>{feature}</span>
              </li>
            ))}
          </ul>
        </div>
      </aside>
    </div>
  )
}
