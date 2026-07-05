"use client"

import { useState, useTransition } from "react"
import { useRouter } from "next/navigation"
import { apiClient } from "@/lib/client/api-client.ts"
import { ApiClientError } from "@/lib/client/api-client.types.ts"
import { ssoLoginUrl, useSsoAvailability } from "@/lib/client/sso-availability"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"

export function LoginForm() {
  const router = useRouter()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [isPending, startTransition] = useTransition()
  const availability = useSsoAvailability()
  const ssoHref = ssoLoginUrl(availability?.protocol ?? null)

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)

    startTransition(async () => {
      try {
        const data = await apiClient<{
          user?: { id: string; email: string; role: string; status: string }
          mfa_required?: boolean
        }>("/api/v1/auth/login", {
          method: "POST",
          body: { identifier: email, password },
          suppressUnauthorizedRedirect: true,
          skipCsrf: true,
        })
        if (data.mfa_required) {
          // The pending-MFA token rides in an HttpOnly cookie the browser sends
          // with the verify request — nothing to stash client-side.
          router.push("/login/verify")
        } else if (data.user?.status === "pending") {
          router.push("/pending")
          router.refresh()
        } else {
          router.push("/")
          router.refresh()
        }
      } catch (err) {
        if (err instanceof ApiClientError) {
          const body = err.body as { detail?: string; error?: string } | null
          setError(body?.detail ?? body?.error ?? "Login failed. Please try again.")
        } else {
          setError("Login failed. Please try again.")
        }
      }
    })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {availability?.enabled && ssoHref && (
        <>
          <a
            href={ssoHref}
            className="inline-flex w-full items-center justify-center rounded-lg border border-[var(--color-accent)] bg-[var(--color-accent)] px-4 py-3 text-sm font-semibold text-[var(--color-accent-on)] hover:bg-[var(--color-accent-hover)] transition-colors focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
          >
            Sign in with SSO
          </a>
          <div className="flex items-center gap-3 text-xs text-[var(--color-text-secondary)]">
            <div className="h-px flex-1 bg-[var(--color-border)]" />
            or
            <div className="h-px flex-1 bg-[var(--color-border)]" />
          </div>
        </>
      )}
      <FormField label="Email or username" htmlFor="email">
        <Input
          id="email"
          type="text"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@example.com or username"
          required
          autoComplete="username"
          autoFocus
        />
      </FormField>

      <FormField label="Password" htmlFor="password">
        <div className="relative">
          <Input
            id="password"
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            required
            autoComplete="current-password"
            className="pr-10"
          />
          <button
            type="button"
            onClick={() => setShowPassword((value) => !value)}
            aria-label={showPassword ? "Hide password" : "Show password"}
            className="absolute inset-y-0 right-0 flex w-10 items-center justify-center rounded-r-md text-[var(--color-text-secondary)] transition-colors hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--color-accent)]"
          >
            {showPassword ? <EyeOffIcon /> : <EyeIcon />}
          </button>
        </div>
      </FormField>

      {error && (
        <div className="rounded-lg bg-[var(--color-severity-critical-subtle)] border border-[var(--color-severity-critical-border)] px-3 py-2.5 text-sm text-[var(--color-severity-critical-text)]">
          {error}
        </div>
      )}

      <button
        type="submit"
        disabled={isPending || !email.trim() || !password}
        className="w-full py-3 px-4 cursor-pointer bg-[var(--color-accent)] text-[var(--color-accent-on)] text-sm font-semibold rounded-lg hover:bg-[var(--color-accent-hover)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
      >
        {isPending ? "Signing in…" : "Sign in"}
      </button>
    </form>
  )
}

function EyeIcon() {
  return (
    <svg
      aria-hidden="true"
      className="h-4 w-4"
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="1.8"
      viewBox="0 0 24 24"
    >
      <path d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178Z" />
      <path d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />
    </svg>
  )
}

function EyeOffIcon() {
  return (
    <svg
      aria-hidden="true"
      className="h-4 w-4"
      fill="none"
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="1.8"
      viewBox="0 0 24 24"
    >
      <path d="m3 3 18 18" />
      <path d="M10.58 10.58A2 2 0 0 0 12 14a2 2 0 0 0 1.42-.58" />
      <path d="M9.88 5.09A10.45 10.45 0 0 1 12 4.88c4.48 0 8.27 2.94 9.54 7a10.56 10.56 0 0 1-2.2 3.57" />
      <path d="M6.52 6.52a10.55 10.55 0 0 0-4.06 5.36c1.27 4.06 5.06 7 9.54 7 1.17 0 2.29-.19 3.34-.54" />
    </svg>
  )
}
