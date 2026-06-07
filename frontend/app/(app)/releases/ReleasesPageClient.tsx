"use client"

import { useState } from "react"
import { PageHeader } from "@/components/layout/PageHeader"
import { ReleasesIcon } from "@/lib/shared/ui/page-icons"
import { ReleasesPageContent } from "./ReleasesPageContent"

export function ReleasesPageClient() {
  const [count, setCount] = useState<number | null>(null)
  return (
    <>
      <PageHeader
        icon={<ReleasesIcon />}
        title="Releases"
        description="Pre-release scan history across all repositories"
        count={count}
      />
      <ReleasesPageContent onCountChange={setCount} />
    </>
  )
}
