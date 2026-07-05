"use client"

import { useState } from "react"
import { PageHeader } from "@/components/layout/PageHeader"
import { DashboardTabs } from "@/components/shared/DashboardTabs"

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "insights", label: "Insights" },
  { id: "health", label: "Health" },
  { id: "settings", label: "Settings" },
] as const

export default function IacSecurityDashboardPage() {
  const [activeTab, setActiveTab] = useState<typeof TABS[number]["id"]>("overview")

  return (
    <>
      <PageHeader
        icon={<IacIcon />}
        title="IaC Security"
        description="Detects misconfigurations in infrastructure-as-code templates"
      />
      <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-8 space-y-8">
        <DashboardTabs tabs={TABS} activeTab={activeTab} onChange={setActiveTab} />

        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-surface)] p-8">
          <div className="max-w-lg">
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-[var(--color-text-tertiary)]">
              In development
            </p>
            <h3 className="mt-3 text-sm font-semibold text-[var(--color-text-primary)]">
              IaC Security scanning is not available yet
            </h3>
            <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
              Infrastructure as Code scanning will detect misconfigurations in Terraform, CloudFormation, Kubernetes manifests, and other IaC templates before they reach production. This feature is being built.
            </p>
          </div>
        </div>
      </main>
    </>
  )
}

function IacIcon() {
  return (
    <div className="p-1.5 bg-[var(--color-accent-subtle)] rounded-lg">
      <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-[var(--color-accent)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75 12 2.25l8.25 4.5v10.5L12 21.75l-8.25-4.5V6.75Zm5.25 3.75L12 12m0 0 3-1.5M12 12v3.75" />
      </svg>
    </div>
  )
}
