"use client"

import { useState, useTransition } from "react"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Modal } from "./Modal"
import { apiClient } from "@/lib/client/api-client.ts"
import { ApiClientError } from "@/lib/client/api-client.types.ts"

/**
 * Removing the second factor is a high-value action, so it requires a current
 * TOTP code — a hijacked or unattended session can't strip 2FA on its own.
 */
export function DisableTotpModal({
  open,
  onClose,
  onSuccess,
}: {
  open: boolean
  onClose: () => void
  onSuccess: () => void
}) {
  const [code, setCode] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [isPending, startTransition] = useTransition()

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    startTransition(async () => {
      try {
        await apiClient("/api/v1/auth/totp/disable", {
          method: "POST",
          body: { code: code.trim() },
        })
        setCode("")
        onSuccess()
      } catch (err) {
        if (err instanceof ApiClientError) {
          const detail =
            typeof err.body === "object" && err.body !== null && "detail" in err.body
              ? String((err.body as { detail?: unknown }).detail ?? "")
              : ""
          setError(detail || "Failed to disable two-factor authentication.")
        } else {
          setError("Failed to disable two-factor authentication.")
        }
      }
    })
  }

  return (
    <Modal open={open} title="Remove two-factor authentication" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <FormField
          label="Authentication code"
          htmlFor="disable-totp-code"
          hint="Enter a current code from your authenticator app to confirm. Your account will be less secure without 2FA."
          error={error ?? undefined}
        >
          <Input
            id="disable-totp-code"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="123456"
            autoFocus
            invalid={!!error}
          />
        </FormField>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" size="md" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="destructive" size="md" isLoading={isPending} disabled={isPending}>
            {isPending ? "Removing..." : "Remove 2FA"}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
