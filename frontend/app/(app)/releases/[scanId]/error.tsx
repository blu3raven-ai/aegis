"use client"

import { PageErrorFallback } from "@/components/shared/PageErrorFallback"

export default function Error(props: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <PageErrorFallback
      {...props}
      description="We couldn't load this release scan. Try again, or head back to the releases list if the problem persists."
      secondaryAction={{ href: "/releases", label: "Go to releases" }}
    />
  )
}
