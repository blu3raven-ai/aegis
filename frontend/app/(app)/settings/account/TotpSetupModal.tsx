"use client"

import { useEffect, useState, useTransition } from "react"
import { Modal } from "./Modal"
import { apiClient } from "@/lib/client/api-client.ts"
import { ApiClientError } from "@/lib/client/api-client.types.ts"

const cancelBtnClass =
  "rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)]"
const saveBtnClass =
  "rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] disabled:cursor-not-allowed disabled:opacity-50"

export function TotpSetupModal({
  onClose,
  onSuccess,
}: {
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
    apiClient<{ qrDataUrl: string; secret: string }>("/settings/api/account/totp", { method: "POST" })
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
        await apiClient("/settings/api/account/totp/verify", {
          method: "POST",
          body: { code },
        })
        onSuccess()
      } catch (err) {
        if (err instanceof ApiClientError) {
          const body = err.body as { error?: string } | null
          setError(body?.error ?? "Invalid code.")
        } else {
          setError("Invalid code.")
        }
      }
    })
  }

  return (
    <Modal title="Set up two-factor authentication" onClose={onClose}>
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
              autoFocus
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2.5 text-center font-mono text-sm tracking-widest focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)]/30"
            />
          </div>
          {error && <p className="text-sm text-[var(--color-severity-critical)]">{error}</p>}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className={cancelBtnClass}>Cancel</button>
            <button type="submit" disabled={isPending || code.length !== 6} className={saveBtnClass}>
              {isPending ? "Verifying..." : "Verify and enable"}
            </button>
          </div>
        </form>
      )}
    </Modal>
  )
}
