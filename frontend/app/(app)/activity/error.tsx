"use client"

import { PageErrorFallback } from "@/components/shared/PageErrorFallback"

export default function Error(props: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return <PageErrorFallback {...props} />
}
