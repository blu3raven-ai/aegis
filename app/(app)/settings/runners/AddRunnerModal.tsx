"use client"

import { useEffect, useState } from "react"
import { RUNNERS_API } from "@/lib/shared/api-paths"

interface Props {
  portalUrl: string
  onClose: () => void
}

function CopyableBlock({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    void navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div>
      <p className="mb-1 text-xs font-semibold text-[var(--color-text-secondary)]">{label}</p>
      <div
        className="relative cursor-pointer rounded-lg bg-[var(--color-surface-raised)] p-3 pr-16 font-mono text-xs text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-border)]"
        onClick={handleCopy}
        title="Click to copy"
      >
        <code className="block break-all">{text}</code>
        <span className="absolute right-2 top-1/2 -translate-y-1/2 rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-0.5 text-[10px] font-medium text-[var(--color-text-secondary)]">
          {copied ? "Copied" : "Copy"}
        </span>
      </div>
    </div>
  )
}

export function AddRunnerModal({ portalUrl, onClose }: Props) {
  const [token, setToken] = useState<string | null>(null)
  const [expiresAt, setExpiresAt] = useState<string | null>(null)
  const [remainingSeconds, setRemainingSeconds] = useState<number>(600)
  const [error, setError] = useState<string | null>(null)
  const [platform, setPlatform] = useState<"linux" | "macos">("linux")

  useEffect(() => {
    async function generate() {
      try {
        const res = await fetch(RUNNERS_API.tokens, { method: "POST" })
        if (!res.ok) {
          setError("Failed to generate token")
          return
        }
        const data = await res.json()
        setToken(data.token)
        setExpiresAt(data.expiresAt)
      } catch {
        setError("Failed to generate token")
      }
    }
    void generate()
  }, [])

  useEffect(() => {
    if (!expiresAt) return
    const interval = setInterval(() => {
      const remaining = Math.max(0, Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000))
      setRemainingSeconds(remaining)
      if (remaining <= 0) clearInterval(interval)
    }, 1000)
    return () => clearInterval(interval)
  }, [expiresAt])

  const configureCmd = token
    ? `./vuln-runner configure --url ${portalUrl} --token ${token}`
    : "..."

  const minutes = Math.floor(remainingSeconds / 60)
  const seconds = remainingSeconds % 60
  const expired = remainingSeconds <= 0

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={onClose}>
      <div
        className="mx-4 w-full max-w-lg rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-6 shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between">
          <div>
            <h3 className="text-lg font-semibold text-[var(--color-text-primary)]">Add runner</h3>
            <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
              Run these commands on your remote machine.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-semibold text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)]"
          >
            Close
          </button>
        </div>

        {error ? (
          <div className="mt-4 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400">
            {error}
          </div>
        ) : (
          <div className="mt-6 space-y-4">
            {/* Token expiry countdown */}
            <div className={`flex items-center gap-2 text-xs font-medium ${expired ? "text-red-500" : "text-[var(--color-text-secondary)]"}`}>
              <span className={`h-2 w-2 rounded-full ${expired ? "bg-red-500" : "bg-emerald-500"}`} />
              {expired
                ? "Token expired — close and generate a new one"
                : `Token expires in ${minutes}:${String(seconds).padStart(2, "0")}`
              }
            </div>

            {/* Platform tabs */}
            <div className="flex gap-2">
              {(["linux", "macos"] as const).map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setPlatform(p)}
                  className={`rounded-lg border px-3 py-1.5 text-xs font-medium ${
                    platform === p
                      ? "border-[var(--color-accent)] bg-[var(--color-accent-subtle)] text-[var(--color-accent)]"
                      : "border-[var(--color-border)] text-[var(--color-text-secondary)]"
                  }`}
                >
                  {p === "linux" ? "Linux" : "macOS"}
                </button>
              ))}
            </div>

            <CopyableBlock
              label="1. Install dependencies"
              text="pip install httpx click"
            />

            <CopyableBlock
              label="2. Configure"
              text={configureCmd}
            />

            <CopyableBlock
              label="3. Start"
              text="python -m runner.vuln_runner start"
            />

            <p className="text-xs text-[var(--color-text-secondary)]">
              After the runner connects, it will appear as "Pending Approval". An admin must approve it before it can receive scan jobs.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
