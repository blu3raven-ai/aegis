"use client"

import { useEffect, useState, useTransition } from "react"
import { Button } from "@/components/ui/Button"
import { FormField } from "@/components/ui/FormField"
import { Input } from "@/components/ui/Input"
import { Modal } from "./Modal"
import { apiClient } from "@/lib/client/api-client.ts"
import { ApiClientError } from "@/lib/client/api-client.types.ts"

export function TotpSetupModal({
  open,
  onClose,
  onSuccess,
}: {
  open: boolean
  onClose: () => void
  onSuccess: () => void
}) {
  const [step, setStep] = useState<"loading" | "scan" | "error">("loading")
  const [qrDataUrl, setQrDataUrl] = useState("")
  const [secret, setSecret] = useState("")
  const [code, setCode] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [isPending, startTransition] = useTransition()

  useEffect(() => {
    apiClient<{ qrDataUrl: string; secret: string }>(
      "/api/v1/auth/totp/enroll",
      { method: "POST" },
    )
      .then((data) => {
        setQrDataUrl(data.qrDataUrl)
        setSecret(data.secret)
        setStep("scan")
      })
      .catch(() => setStep("error"))
  }, [])

  function handleVerify(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    startTransition(async () => {
      try {
        await apiClient("/api/v1/auth/totp/verify", {
          method: "POST",
          body: { code },
        })
        onSuccess()
      } catch (err) {
        if (err instanceof ApiClientError) {
          const detail =
            typeof err.body === "object" && err.body !== null && "detail" in err.body
              ? String((err.body as { detail?: unknown }).detail ?? "")
              : ""
          setError(detail || "Invalid code.")
        } else {
          setError("Invalid code.")
        }
      }
    })
  }

  return (
    <Modal open={open} title="Set up two-factor authentication" onClose={onClose}>
      {step === "loading" && (
        <p className="py-4 text-center text-sm text-[var(--color-text-secondary)]">
          Generating code...
        </p>
      )}
      {step === "error" && (
        <p className="py-4 text-center text-sm text-[var(--color-severity-critical)]">
          Failed to start setup. Close and try again.
        </p>
      )}
      {step === "scan" && (
        <form onSubmit={handleVerify} className="space-y-4">
          <p className="text-sm text-[var(--color-text-secondary)]">
            Scan this QR code with your authenticator app, then enter the 6-digit code to confirm.
          </p>
          <div className="flex justify-center">
            <img src={qrDataUrl} alt="QR code for authenticator app" className="h-44 w-44 rounded-lg" />
          </div>
          <details className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 py-2">
            <summary className="cursor-pointer text-xs font-medium text-[var(--color-text-secondary)]">
              Cannot scan? Enter code manually
            </summary>
            <code className="mt-2 block break-all font-mono text-xs text-[var(--color-text-primary)]">
              {secret}
            </code>
          </details>
          <FormField label="Verification code" htmlFor="totp-code" error={error ?? undefined}>
            <Input
              id="totp-code"
              type="text"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
              placeholder="000000"
              required
              autoFocus
              invalid={!!error}
              className="text-center font-mono tracking-widest"
            />
          </FormField>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" size="md" onClick={onClose}>Cancel</Button>
            <Button type="submit" variant="primary" size="md" isLoading={isPending} disabled={isPending || code.length !== 6}>
              {isPending ? "Verifying..." : "Verify and enable"}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  )
}
