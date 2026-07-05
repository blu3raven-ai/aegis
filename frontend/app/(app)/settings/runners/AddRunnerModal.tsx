"use client"

import { useEffect, useState } from "react"
import { generateRunnerToken } from "@/lib/client/settings/use-runners"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { Sheet } from "@/components/ui/Sheet"

interface Props {
  open: boolean
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
        className="relative cursor-pointer rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-3 pr-16 font-mono text-xs text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-border)]"
        onClick={handleCopy}
        title="Click to copy"
      >
        <code className="block break-all">{text}</code>
        <span className="absolute right-2 top-1/2 -translate-y-1/2 rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-0.5 text-2xs font-medium text-[var(--color-text-secondary)]">
          {copied ? "Copied" : "Copy"}
        </span>
      </div>
    </div>
  )
}

export function AddRunnerModal({ open, portalUrl, onClose }: Props) {
  const [token, setToken] = useState<string | null>(null)
  const [expiresAt, setExpiresAt] = useState<string | null>(null)
  const [remainingSeconds, setRemainingSeconds] = useState<number>(600)
  const [error, setError] = useState<string | null>(null)
  const [platform, setPlatform] = useState<"linux" | "macos">("linux")

  useEffect(() => {
    if (!open) return
    async function generate() {
      try {
        const data = await generateRunnerToken()
        setToken(data.token)
        setExpiresAt(data.expiresAt)
      } catch {
        setError("Failed to generate token")
      }
    }
    void generate()
  }, [open])

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
    <Sheet
      open={open}
      onClose={onClose}
      title="Add runner"
      description="Run these commands on your remote machine."
      size="md"
    >
      {error ? (
        <div className="rounded-lg border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] p-4 text-sm text-[var(--color-severity-critical-text)]">
          {error}
        </div>
      ) : (
        <div className="space-y-4">
          {/* Token expiry countdown */}
          <div className={`flex items-center gap-2 text-xs font-medium ${expired ? "text-[var(--color-severity-critical-text)]" : "text-[var(--color-text-secondary)]"}`}>
            <span className={`h-2 w-2 rounded-full ${expired ? "bg-[var(--color-severity-critical)]" : "bg-[var(--color-status-ok)]"}`} />
            {expired
              ? "Token expired — close and generate a new one"
              : `Token expires in ${minutes}:${String(seconds).padStart(2, "0")}`
            }
          </div>

          <SegmentedControl
            ariaLabel="Platform"
            value={platform}
            onChange={setPlatform}
            options={[
              { id: "linux", label: "Linux" },
              { id: "macos", label: "macOS" },
            ]}
          />

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
            After the runner connects, it will appear as &ldquo;Pending Approval&rdquo;. An admin must approve it before it can receive scan jobs.
          </p>
        </div>
      )}
    </Sheet>
  )
}
