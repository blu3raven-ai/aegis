"use client"

import { Download } from "lucide-react"
import { Button } from "@/components/ui/Button"

interface Props {
  frameworkId: string | null
}

export function AttestationExportButton({ frameworkId }: Props) {
  const disabled = !frameworkId
  const href = frameworkId
    ? `/api/v1/compliance/frameworks/${encodeURIComponent(frameworkId)}/attestation.pdf`
    : undefined

  if (disabled) {
    return (
      <Button
        variant="secondary"
        disabled
        title="Select a framework first"
        leadingIcon={<Download />}
      >
        Export attestation
      </Button>
    )
  }

  return (
    <a
      href={href}
      download
      className="inline-flex h-8 items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 text-xs font-semibold text-[var(--color-text-primary)] transition-colors hover:border-[var(--color-border-strong)] hover:bg-[var(--color-bg-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--color-surface)]"
    >
      <Download className="h-3.5 w-3.5 shrink-0" />
      Export attestation
    </a>
  )
}
