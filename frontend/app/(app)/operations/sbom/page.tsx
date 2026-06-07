"use client"

import { PageHeader } from "@/components/layout/PageHeader"
import { SbomIcon } from "@/lib/shared/ui/page-icons"
import { SbomExplorer } from "../SbomExplorer"

export default function SbomPage() {
  return (
    <>
      <PageHeader
        icon={<SbomIcon />}
        title="SBOM Explorer"
        description="Search and query your software bill of materials"
      />
      <main className="mx-auto max-w-7xl px-6 py-8">
        <SbomExplorer />
      </main>
    </>
  )
}
