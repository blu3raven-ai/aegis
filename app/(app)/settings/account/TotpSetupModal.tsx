"use client"

import { useEffect, useState, useTransition } from "react"
import { Modal } from "./Modal"

const cancelBtnClass =
  "rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-raised)]"
const saveBtnClass =
  "rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-[var(--color-accent-hover)] disabled:cursor-not-allowed disabled:opacity-50"

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
    fetch("/api/settings/account/totp", { method: "POST" })
      .then((response) => {
        if (!response.ok) throw new Error("Setup failed.")
        return response.json() as Promise<{ qrDataUrl: string; secret: string }>
      })
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
      const res = await fetch("/api/settings/account/totp/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      })
      const data = await res.json().catch(() => ({})) as { error?: string }
      if (!res.ok) {
        setError(data.error ?? "Invalid code.")
        return
      }
      onSuccess()
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
        <p className="py-4 text-center text-sm text-red-500">
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
          {error && <p className="text-sm text-red-500">{error}</p>}
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
