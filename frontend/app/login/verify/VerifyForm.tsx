"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"
import { useState, useTransition } from "react"
import { apiClient } from "@/lib/client/api-client.ts"
import { ApiClientError } from "@/lib/client/api-client.types.ts"

export function VerifyForm() {
  const router = useRouter()
  const [code, setCode] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [isExpired, setIsExpired] = useState(false)
  const [isPending, startTransition] = useTransition()

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setIsExpired(false)

    startTransition(async () => {
      const pending_token = sessionStorage.getItem("mfa_pending_token") ?? ""
      try {
        await apiClient("/auth/login/verify", {
          method: "POST",
          body: { pending_token, code },
          suppressUnauthorizedRedirect: true,
          skipCsrf: true,
        })
        sessionStorage.removeItem("mfa_pending_token")
        router.push("/")
        router.refresh()
      } catch (err) {
        if (err instanceof ApiClientError) {
          if (err.status === 401) {
            setIsExpired(true)
            sessionStorage.removeItem("mfa_pending_token")
            setError("Session expired. Please sign in again.")
            return
          }
          const body = err.body as { detail?: string; error?: string } | null
          setError(body?.detail ?? body?.error ?? "Invalid code. Try again.")
        } else {
          setError("Invalid code. Try again.")
        }
      }
    })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      <div>
        <label htmlFor="code" className="mb-1.5 block text-sm font-medium text-[var(--color-text-primary)]">
          Verification code
        </label>
        <input
          id="code"
          type="text"
          inputMode="numeric"
          pattern="[0-9]{6}"
          maxLength={6}
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          placeholder="000000"
          required
          autoComplete="one-time-code"
          autoFocus
          className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-3 text-center font-mono text-sm tracking-widest text-[var(--color-text-primary)] placeholder:text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-text-secondary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
        />
      </div>

      {error && (
        <div className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-2.5 text-sm text-[var(--color-severity-critical)]">
          {error}
          {isExpired && (
            <>
              {" "}
              <Link href="/login" className="underline">
                Sign in again
              </Link>
            </>
          )}
        </div>
      )}

      <button
        type="submit"
        disabled={isPending || code.length !== 6}
        className="w-full cursor-pointer rounded-lg bg-[var(--color-accent)] px-4 py-3 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] disabled:cursor-not-allowed disabled:opacity-50"
      >
        {isPending ? "Verifying..." : "Verify"}
      </button>

      <p className="text-center text-xs text-[var(--color-text-secondary)]">
        <Link href="/login" className="hover:text-[var(--color-text-primary)]">
          Back to sign in
        </Link>
      </p>
    </form>
  )
}
