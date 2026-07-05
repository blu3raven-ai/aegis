"use client"

import { Download } from "lucide-react"
import { Button, buttonClassName, buttonIconClassName } from "@/components/ui/Button"

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
        size="md"
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
      className={buttonClassName({ variant: "secondary", size: "md" })}
    >
      <Download className={`${buttonIconClassName("md")} shrink-0`} />
      Export attestation
    </a>
  )
}
