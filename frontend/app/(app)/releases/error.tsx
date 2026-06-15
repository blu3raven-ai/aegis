"use client"

import { PageErrorFallback } from "@/components/shared/PageErrorFallback"

export default function Error(props: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <PageErrorFallback
      {...props}
      description="We couldn't load releases. Try again, or head back home if the problem persists."
    />
  )
}
