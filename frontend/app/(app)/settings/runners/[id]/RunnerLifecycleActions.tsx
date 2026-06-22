"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import {
  approveRunner,
  deleteRunner,
  revokeRunner,
  rotateRunnerToken,
} from "@/lib/client/settings/use-runners"
import { Button } from "@/components/ui/Button"
import { Dialog } from "@/components/layout/Dialog"

interface Props {
  runnerId: string
  status: string
  onChange: () => void
}

export function RunnerLifecycleActions({ runnerId, status, onChange }: Props) {
  const router = useRouter()
  const [busy, setBusy] = useState<null | "approve" | "revoke" | "rotate" | "delete">(null)
  const [confirm, setConfirm] = useState<null | "revoke" | "rotate" | "delete">(null)
  const [rotatedToken, setRotatedToken] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const isPending = status === "pending_approval"
  const isRevoked = status === "revoked"

  async function handleApprove() {
    setBusy("approve")
    setError(null)
    try {
      await approveRunner(runnerId)
      onChange()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Approve failed")
    }
    setBusy(null)
  }

  async function handleRevoke() {
    setBusy("revoke")
    setError(null)
    try {
      await revokeRunner(runnerId)
      onChange()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Revoke failed")
    }
    setBusy(null)
    setConfirm(null)
  }

  async function handleRotate() {
    setBusy("rotate")
    setError(null)
    try {
      const newToken = await rotateRunnerToken(runnerId)
      setRotatedToken(newToken)
      onChange()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Rotate failed")
    }
    setBusy(null)
    setConfirm(null)
  }

  async function handleDelete() {
    setBusy("delete")
    setError(null)
    try {
      await deleteRunner(runnerId)
      router.push("/settings/runners")
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed")
      setBusy(null)
      setConfirm(null)
    }
  }

  function copyToken() {
    if (!rotatedToken) return
    void navigator.clipboard.writeText(rotatedToken)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        {isPending && (
          <Button
            variant="primary"
            size="sm"
            onClick={handleApprove}
            isLoading={busy === "approve"}
            disabled={busy !== null}
          >
            Approve
          </Button>
        )}
        {!isPending && !isRevoked && (
          <Button
            variant="secondary"
            size="sm"
            onClick={() => setConfirm("revoke")}
            disabled={busy !== null}
          >
            Revoke
          </Button>
        )}
        {!isRevoked && (
          <Button
            variant="secondary"
            size="sm"
            onClick={() => setConfirm("rotate")}
            disabled={busy !== null}
          >
            Rotate token
          </Button>
        )}
        <Button
          variant="destructive"
          size="sm"
          onClick={() => setConfirm("delete")}
          disabled={busy !== null}
        >
          Delete
        </Button>
      </div>

      {error && (
        <p className="mt-2 text-sm text-[var(--color-severity-critical)]">{error}</p>
      )}

      <Dialog
        open={confirm === "revoke"}
        onClose={() => setConfirm(null)}
        onConfirm={handleRevoke}
        title="Revoke this runner?"
        description="The runner's current auth token will stop working immediately. It will no longer receive new jobs. Re-registering requires a fresh registration token."
        confirmLabel={busy === "revoke" ? "Revoking…" : "Revoke"}
        variant="danger"
      />

      <Dialog
        open={confirm === "rotate"}
        onClose={() => setConfirm(null)}
        onConfirm={handleRotate}
        title="Rotate the runner's auth token?"
        description="The current token stops working immediately. You'll need to copy the new token to the runner host before it can poll again."
        confirmLabel={busy === "rotate" ? "Rotating…" : "Rotate"}
        variant="danger"
      />

      <Dialog
        open={confirm === "delete"}
        onClose={() => setConfirm(null)}
        onConfirm={handleDelete}
        title="Delete this runner permanently?"
        description="The runner's record, auth tokens, and heartbeat history will be removed. Active jobs assigned to it will be re-queued. This cannot be undone."
        confirmLabel={busy === "delete" ? "Deleting…" : "Delete"}
        variant="danger"
      />

      <Dialog
        open={rotatedToken !== null}
        onClose={() => {
          setRotatedToken(null)
          setCopied(false)
        }}
        title="New auth token"
      >
        <p className="text-sm text-[var(--color-text-secondary)]">
          Copy this token to the runner host now — it will not be shown again.
        </p>
        <div className="mt-4">
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-3 font-[family-name:var(--font-jetbrains-mono)] text-xs break-all text-[var(--color-text-primary)]">
            {rotatedToken}
          </div>
        </div>
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="secondary" size="sm" onClick={copyToken}>
            {copied ? "Copied" : "Copy"}
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={() => {
              setRotatedToken(null)
              setCopied(false)
            }}
          >
            Done
          </Button>
        </div>
      </Dialog>
    </>
  )
}
