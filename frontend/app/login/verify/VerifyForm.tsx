"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"
import { useState, useTransition } from "react"
import { apiClient } from "@/lib/client/api-client.ts"
import { ApiClientError } from "@/lib/client/api-client.types.ts"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"

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
      try {
        // The pending-MFA token rides in an HttpOnly cookie set at login; the
        // browser sends it automatically, so we only submit the code.
        await apiClient("/api/v1/auth/login/verify", {
          method: "POST",
          body: { code },
          suppressUnauthorizedRedirect: true,
          skipCsrf: true,
        })
        router.push("/")
        router.refresh()
      } catch (err) {
        if (err instanceof ApiClientError) {
          if (err.status === 401) {
            setIsExpired(true)
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
      <FormField label="Verification code" htmlFor="code">
        <Input
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
          className="text-center font-mono tracking-widest"
        />
      </FormField>

      {error && (
        <div role="alert" className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] px-3 py-2.5 text-sm text-[var(--color-severity-critical-text)]">
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

      <Button
        type="submit"
        variant="primary"
        size="md"
        disabled={isPending || code.length !== 6}
        className="w-full"
      >
        {isPending ? "Verifying..." : "Verify"}
      </Button>

      <p className="text-center text-xs text-[var(--color-text-secondary)]">
        <Link href="/login" className="hover:text-[var(--color-text-primary)]">
          Back to sign in
        </Link>
      </p>
    </form>
  )
}
