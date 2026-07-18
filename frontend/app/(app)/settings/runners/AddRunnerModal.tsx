"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { Check } from "lucide-react"
import { generateRunnerToken, fetchRunners, approveRunner } from "@/lib/client/settings/use-runners"
import { SegmentedControl } from "@/components/ui/SegmentedControl"
import { Button } from "@/components/ui/Button"
import { Sheet } from "@/components/ui/Sheet"
import { Skeleton } from "@/components/ui/Skeleton"
import { HostReachabilityNote } from "@/components/shared/HostReachabilityNote"
import { useSSE } from "@/components/providers/SSEProvider"

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
      <button
        type="button"
        className="relative block w-full cursor-pointer rounded-md border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-3 pr-16 text-left font-mono text-xs text-[var(--color-text-primary)] transition-colors hover:bg-[var(--color-border)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)]"
        onClick={handleCopy}
        aria-label={copied ? `${label}: copied` : `Copy ${label.toLowerCase()}`}
      >
        <code className="block break-all">{text}</code>
        <span
          aria-hidden
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-0.5 text-2xs font-medium text-[var(--color-text-secondary)]"
        >
          {copied ? "Copied" : "Copy"}
        </span>
      </button>
    </div>
  )
}

export function AddRunnerModal({ open, portalUrl, onClose }: Props) {
  const [token, setToken] = useState<string | null>(null)
  const [expiresAt, setExpiresAt] = useState<string | null>(null)
  const [remainingSeconds, setRemainingSeconds] = useState<number>(600)
  const [error, setError] = useState<string | null>(null)
  const [platform, setPlatform] = useState<"linux" | "macos">("linux")
  const [method, setMethod] = useState<"docker" | "python">("docker")
  // Runner IDs that existed before this modal opened — so a new one appearing is
  // the one being set up, not an existing runner's heartbeat.
  const knownRunnerIdsRef = useRef<Set<string>>(new Set())
  const [connected, setConnected] = useState<{ runnerId: string; name: string } | null>(null)
  const [approving, setApproving] = useState(false)
  const [approved, setApproved] = useState(false)

  useEffect(() => {
    if (!open) return
    setConnected(null)
    setApproved(false)
    void (async () => {
      try {
        const r = await fetchRunners()
        knownRunnerIdsRef.current = new Set((r.runners || []).map((x) => x.id))
      } catch {
        /* best-effort snapshot; a false "connected" is harmless */
      }
    })()
    void (async () => {
      try {
        const data = await generateRunnerToken()
        setToken(data.token)
        setExpiresAt(data.expiresAt)
      } catch {
        setError("Failed to generate token")
      }
    })()
  }, [open])

  // A new runner heartbeating while this modal is open is the one being set up.
  useSSE("runner.status", (e) => {
    if (!open || connected || knownRunnerIdsRef.current.has(e.runnerId)) return
    setConnected({ runnerId: e.runnerId, name: e.name })
  })

  const handleApprove = useCallback(async () => {
    if (!connected) return
    setApproving(true)
    try {
      await approveRunner(connected.runnerId)
      setApproved(true)
    } catch {
      setError("Failed to approve runner")
    } finally {
      setApproving(false)
    }
  }, [connected])

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

  const dockerCmd = token
    ? `docker run -d --restart unless-stopped -e BACKEND_URL=${portalUrl} -e RUNNER_REGISTRATION_TOKEN=${token} -v aegis-runner-workspace:/workspace ghcr.io/blu3raven-ai/aegis-runner:latest`
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
      variant="modal"
      size="md"
    >
      {error ? (
        <div className="rounded-md border border-[var(--color-severity-critical-border)] bg-[var(--color-severity-critical-subtle)] p-4 text-sm text-[var(--color-severity-critical-text)]">
          {error}
        </div>
      ) : (
        <div className="space-y-4">
          {/* Token expiry countdown */}
          <div className={`flex items-center gap-2 text-xs font-medium ${expired ? "text-[var(--color-severity-critical-text)]" : "text-[var(--color-text-secondary)]"}`}>
            <span className={`h-2 w-2 rounded-full ${expired ? "bg-[var(--color-severity-critical)]" : "bg-[var(--color-status-ok)]"}`} />
            {expired
              ? "Token expired. Close and generate a new one"
              : `Token expires in ${minutes}:${String(seconds).padStart(2, "0")}`
            }
          </div>

          <SegmentedControl
            ariaLabel="Install method"
            value={method}
            onChange={setMethod}
            options={[
              { id: "docker", label: "Docker" },
              { id: "python", label: "Python" },
            ]}
          />

          <HostReachabilityNote origin={portalUrl} audience="the runner machine" />

          {!token ? (
            <div className="space-y-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : method === "docker" ? (
            <CopyableBlock label="Run the runner" text={dockerCmd} />
          ) : (
            <>
              <SegmentedControl
                ariaLabel="Platform"
                value={platform}
                onChange={setPlatform}
                options={[
                  { id: "linux", label: "Linux" },
                  { id: "macos", label: "macOS" },
                ]}
              />
              <CopyableBlock label="1. Install dependencies" text="pip install httpx click" />
              <CopyableBlock label="2. Configure" text={configureCmd} />
              <CopyableBlock label="3. Start" text="python -m runner.vuln_runner start" />
            </>
          )}

          {connected ? (
            <div
              className="rounded-md border border-[var(--color-status-ok-border)] bg-[var(--color-status-ok-subtle)] p-3"
              role="status"
              aria-live="polite"
            >
              <div className="flex items-center gap-2 text-sm font-medium text-[var(--color-status-ok-text)]">
                <Check className="h-4 w-4 shrink-0" aria-hidden />
                {approved
                  ? `${connected.name} approved. Ready to receive scans`
                  : `${connected.name} connected`}
              </div>
              {!approved && (
                <div className="mt-2 flex flex-wrap items-center gap-3">
                  <span className="text-xs text-[var(--color-text-secondary)]">
                    Approve it so it can receive scan jobs.
                  </span>
                  <Button size="xs" onClick={handleApprove} isLoading={approving}>
                    Approve runner
                  </Button>
                </div>
              )}
            </div>
          ) : (
            <div
              className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]"
              role="status"
              aria-live="polite"
            >
              <span className="h-3.5 w-3.5 shrink-0 animate-spin rounded-full border-2 border-[var(--color-border)] border-t-[var(--color-accent)] motion-reduce:animate-none" />
              Waiting for the runner to connect…
            </div>
          )}
        </div>
      )}
    </Sheet>
  )
}
