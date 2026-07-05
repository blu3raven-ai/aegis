"use client"

import { PageHeader } from "@/components/layout/PageHeader"
import { HomeIcon } from "@/lib/shared/ui/page-icons"
import { HomeDashboard } from "./HomeDashboard"

export function HomeShell() {
  return (
    <>
      <PageHeader icon={<HomeIcon />} title="Home" />
      <main className="px-6 py-8">
        <HomeDashboard />
      </main>
    </>
  )
}
