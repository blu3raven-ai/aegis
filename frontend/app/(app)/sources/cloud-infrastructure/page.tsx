"use client"

import { PageHeader } from "@/components/layout/PageHeader"
import { CloudIcon } from "@/lib/shared/ui/page-icons"
import { Card } from "@/components/ui/Card"

export default function CloudInfrastructurePage() {
  return (
    <>
      <PageHeader
        icon={<CloudIcon />}
        title="Cloud Infrastructure"
        description="No accounts connected"
      />
      <main className="px-6 py-8">
        <Card padding="none" className="rounded-md p-8">
          <div className="max-w-lg">
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
              In Development
            </p>
            <h2 className="mt-3 text-base font-semibold text-[var(--color-text-primary)]">
              Cloud infrastructure scanning is not available yet
            </h2>
            <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
              This will let you connect AWS, Azure, or GCP accounts to scan for infrastructure misconfigurations and compliance issues. You can start with Git Repository or Container Registry sources in the meantime.
            </p>
          </div>
        </Card>
      </main>
    </>
  )
}
