"use client"

import { useCallback, useState } from "react"
import { PageHeader } from "@/components/layout/PageHeader"
import { HomeDashboard } from "./HomeDashboard"
import { InsightsContent } from "@/components/shared/insights/InsightsContent"

type HomeTab = "overview" | "trends"

const TABS: { id: HomeTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "trends", label: "Trends" },
]

function HomeIcon() {
  return (
    <div className="p-1.5 rounded-lg bg-[var(--color-accent-subtle)]">
      <svg
        xmlns="http://www.w3.org/2000/svg"
        className="w-5 h-5 text-[var(--color-accent)]"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={1.8}
      >
        <path strokeLinecap="round" strokeLinejoin="round" d="m2.25 12 8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25" />
      </svg>
    </div>
  )
}

export function HomeShell() {
  const [activeTab, setActiveTab] = useState<HomeTab>("overview")
  const handleTab = useCallback((id: HomeTab) => setActiveTab(id), [])

  return (
    <>
      <PageHeader icon={<HomeIcon />} title="Security Portal" description="Overview" />

      {/* Tab bar — flat at rest, single accent on active */}
      <div className="border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6">
        <div role="tablist" aria-label="Home views" className="mx-auto flex max-w-7xl gap-1">
          {TABS.map((tab) => {
            const active = tab.id === activeTab
            return (
              <button
                key={tab.id}
                role="tab"
                type="button"
                aria-selected={active}
                onClick={() => handleTab(tab.id)}
                className={`-mb-px border-b-2 px-3 py-2.5 text-sm transition-colors ${
                  active
                    ? "border-[var(--color-accent)] font-semibold text-[var(--color-text-primary)]"
                    : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                }`}
              >
                {tab.label}
              </button>
            )
          })}
        </div>
      </div>

      <main className="mx-auto max-w-7xl px-6 py-8">
        {activeTab === "overview" ? <HomeDashboard /> : <InsightsContent hideHeader />}
      </main>
    </>
  )
}
