"use client"

import { useState, useTransition } from "react"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Modal } from "./Modal"
import { apiClient } from "@/lib/client/api-client.ts"
import { ApiClientError } from "@/lib/client/api-client.types.ts"

export function EmailModal({
  open,
  initialEmail,
  onClose,
  onSuccess,
}: {
  open: boolean
  initialEmail: string | null
  onClose: () => void
  onSuccess: () => void
}) {
  const [email, setEmail] = useState(initialEmail ?? "")
  const [currentPassword, setCurrentPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [isPending, startTransition] = useTransition()

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    startTransition(async () => {
      try {
        await apiClient("/api/v1/auth/email", {
          method: "PATCH",
          body: { email: email.trim(), current_password: currentPassword },
        })
        onSuccess()
      } catch (err) {
        if (err instanceof ApiClientError) {
          const detail =
            typeof err.body === "object" && err.body !== null && "detail" in err.body
              ? String((err.body as { detail?: unknown }).detail ?? "")
              : ""
          setError(detail || "Failed to update email.")
        } else {
          setError("Failed to update email.")
        }
      }
    })
  }

  return (
    <Modal open={open} title="Change email" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <FormField
          label="Email address"
          htmlFor="account-email"
          hint="Leave blank to remove your email. You can sign in with email or username."
          error={error ?? undefined}
        >
          <Input
            id="account-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            autoFocus
            autoComplete="email"
            invalid={!!error}
          />
        </FormField>
        <FormField
          label="Current password"
          htmlFor="account-email-password"
          hint="Confirm your password to change your email. Leave blank if you sign in with SSO."
        >
          <Input
            id="account-email-password"
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            placeholder="Current password"
            autoComplete="current-password"
          />
        </FormField>
        <div className="flex justify-end gap-2">
          <Button variant="secondary" size="md" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" size="md" isLoading={isPending} disabled={isPending}>
            {isPending ? "Saving..." : "Save"}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
