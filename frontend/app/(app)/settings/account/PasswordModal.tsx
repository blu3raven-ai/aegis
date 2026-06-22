"use client"

import { useState, useTransition } from "react"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { saveAccountSettings } from "@/lib/client/settings-api"
import { Modal } from "./Modal"

const EYE_OPEN = "M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.964-7.178Z M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"
const EYE_CLOSED = "M3.98 8.223A10.477 10.477 0 0 0 1.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88"

function PasswordField({
  id,
  label,
  value,
  onChange,
  autoFocus,
  autoComplete,
}: {
  id: string
  label: string
  value: string
  onChange: (v: string) => void
  autoFocus?: boolean
  autoComplete?: string
}) {
  const [show, setShow] = useState(false)
  return (
    <FormField label={label} htmlFor={id}>
      <div className="relative">
        <Input
          id={id}
          type={show ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          required
          autoFocus={autoFocus}
          autoComplete={autoComplete}
          className="pr-9"
        />
        <Button
          variant="link"
          size="xs"
          onClick={() => setShow((s) => !s)}
          className="absolute inset-y-0 right-0 flex items-center px-2.5 text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          tabIndex={-1}
          aria-label={show ? "Hide password" : "Show password"}
        >
          <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
            <path d={show ? EYE_CLOSED : EYE_OPEN} />
          </svg>
        </Button>
      </div>
    </FormField>
  )
}

export function PasswordModal({
  open,
  username,
  onClose,
  onSuccess,
}: {
  open: boolean
  username: string
  onClose: () => void
  onSuccess: () => void
}) {
  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmNewPassword, setConfirmNewPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [isPending, startTransition] = useTransition()

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (newPassword !== confirmNewPassword) {
      setError("Passwords do not match.")
      return
    }
    if (currentPassword === newPassword) {
      setError("New password must be different from your current password.")
      return
    }
    startTransition(async () => {
      const result = await saveAccountSettings({
        username,
        currentPassword,
        newPassword,
        confirmNewPassword,
      })
      if (!result.ok) {
        setError(result.error)
        return
      }
      onSuccess()
    })
  }

  return (
    <Modal open={open} title="Change password" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <p className="text-sm text-[var(--color-text-secondary)]">
          Choose a new password for your portal account. You can keep using your current session after the change is saved.
        </p>
        <PasswordField
          id="account-current-password"
          label="Current password"
          value={currentPassword}
          onChange={setCurrentPassword}
          autoFocus
          autoComplete="current-password"
        />
        <PasswordField
          id="account-new-password"
          label="New password"
          value={newPassword}
          onChange={setNewPassword}
          autoComplete="new-password"
        />
        <PasswordField
          id="account-confirm-new-password"
          label="Confirm new password"
          value={confirmNewPassword}
          onChange={setConfirmNewPassword}
          autoComplete="new-password"
        />
        {error && <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button variant="secondary" size="md" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" size="md" isLoading={isPending} disabled={isPending}>
            {isPending ? "Saving..." : "Save password"}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
