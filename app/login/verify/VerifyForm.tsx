"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"
import { useState, useTransition } from "react"

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
      const res = await fetch("/api/login/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      })

      if (res.ok) {
        router.push("/")
        router.refresh()
        return
      }

      if (res.status === 401) {
        setIsExpired(true)
        setError("Session expired. Please sign in again.")
        return
      }

      const data = await res.json().catch(() => ({})) as { error?: string }
      setError(data.error ?? "Invalid code. Try again.")
    })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-primary)]">
          Verification code
        </label>
        <input
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
          className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2.5 text-center font-mono text-sm tracking-widest text-[var(--color-text-primary)] placeholder:text-[var(--color-text-secondary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
        />
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/30 dark:text-red-400">
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
        className="w-full rounded-lg bg-[var(--color-accent)] px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[var(--color-accent-hover)] disabled:cursor-not-allowed disabled:opacity-50"
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
