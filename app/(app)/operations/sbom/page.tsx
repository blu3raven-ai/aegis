"use client"

import { PageHeader } from "@/components/layout/PageHeader"
import { SbomExplorer } from "../SbomExplorer"

function SbomIcon() {
  return (
    <div className="p-1.5 bg-blue-50 dark:bg-blue-950 rounded-lg">
      <svg className="w-5 h-5 text-blue-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
        <path d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 0 1 0 3.75H5.625a1.875 1.875 0 0 1 0-3.75Z" />
      </svg>
    </div>
  )
}

export default function SbomPage() {
  return (
    <>
      <PageHeader
        icon={<SbomIcon />}
        title="SBOM Explorer"
        org="Search and query your software bill of materials"
      />
      <main className="mx-auto max-w-7xl px-6 py-8">
        <SbomExplorer />
      </main>
    </>
  )
}
