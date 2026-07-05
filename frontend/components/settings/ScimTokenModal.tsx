"use client"

import { Button } from "@/components/ui/Button"
import { Sheet } from "@/components/ui/Sheet"

interface Props {
  open: boolean
  token: string
  onClose: () => void
}

export function ScimTokenModal({ open, token, onClose }: Props) {
  const handleCopy = () => {
    navigator.clipboard?.writeText(token).catch(() => {})
  }
  return (
    <Sheet
      open={open}
      onClose={onClose}
      title="SCIM bearer token"
      description="Copy this token into your IdP's SCIM configuration now. It will not be shown again."
      size="md"
      footer={
        <div className="flex justify-end gap-2">
          <Button variant="secondary" size="sm" onClick={handleCopy} aria-label="Copy SCIM token">
            Copy
          </Button>
          <Button variant="primary" size="sm" onClick={onClose}>
            {"I've saved it"}
          </Button>
        </div>
      }
    >
      <code className="block w-full break-all rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface-raised)] px-3 py-2 font-mono text-xs text-[var(--color-text-primary)]">
        {token}
      </code>
    </Sheet>
  )
}
