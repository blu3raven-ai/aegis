"use client"

import { useCallback, useEffect, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import type { SourceCategory } from "@/lib/shared/sources-types"
import { SourcePageShell } from "./_components/SourcePageShell"
import { RepositoriesPanel } from "./_components/RepositoriesPanel"
import { ReposIcon } from "@/lib/shared/ui/page-icons"

type SourcesTab = "code-repositories" | "container-registry" | "repositories"

const TABS: { id: SourcesTab; label: string; description: string }[] = [
  {
    id: "code-repositories",
    label: "Git Repository",
    description: "Connect code hosts to scan repositories for vulnerabilities, secrets, and code issues.",
  },
  {
    id: "container-registry",
    label: "Container Registry",
    description: "Connect container registries to scan images for vulnerabilities.",
  },
  {
    id: "repositories",
    label: "Repositories",
    description: "All assets monitored by Aegis. Coverage and risk at a glance.",
  },
]

function GitRepoIcon() {
  return (
    <svg className="h-5 w-5 text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M14.25 9.75 16.5 12l-2.25 2.25m-4.5 0L7.5 12l2.25-2.25M6 20.25h12A2.25 2.25 0 0 0 20.25 18V6A2.25 2.25 0 0 0 18 3.75H6A2.25 2.25 0 0 0 3.75 6v12A2.25 2.25 0 0 0 6 20.25Z" />
    </svg>
  )
}

function ContainerRegistryIcon() {
  return (
    <svg className="h-5 w-5 text-[var(--color-accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M20.25 7.5l-.625 10.632a2.25 2.25 0 0 1-2.247 2.118H6.622a2.25 2.25 0 0 1-2.247-2.118L3.75 7.5M10 11.25h4M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125Z" />
    </svg>
  )
}

function tabIconNode(id: SourcesTab): React.ReactNode {
  if (id === "code-repositories") return <GitRepoIcon />
  if (id === "container-registry") return <ContainerRegistryIcon />
  return <ReposIcon />
}

interface SourcesIndexClientProps {
  canEdit: boolean
  initialTab: SourcesTab
}

function isSourcesTab(value: string | null): value is SourcesTab {
  return value === "code-repositories" || value === "container-registry" || value === "repositories"
}

export function SourcesIndexClient({ canEdit, initialTab }: SourcesIndexClientProps) {
  const router = useRouter()
  const params = useSearchParams()
  const queryTab = params.get("tab")
  const activeTab: SourcesTab = isSourcesTab(queryTab) ? queryTab : initialTab
  const activeMeta = TABS.find((t) => t.id === activeTab) ?? TABS[0]

  // Modal state lives here so the header button can trigger it without a floating CTA in the content area.
  const [showAdd, setShowAdd] = useState(false)

  // Reset modal when switching tabs so it never carries over.
  useEffect(() => {
    setShowAdd(false)
  }, [activeTab])

  const handleTabChange = useCallback(
    (tab: SourcesTab) => {
      const next = new URLSearchParams(params.toString())
      next.set("tab", tab)
      router.replace(`/sources?${next.toString()}`, { scroll: false })
    },
    [router, params],
  )

  const showAddButton = canEdit && activeTab !== "repositories"

  return (
    <div className="flex h-full flex-col overflow-y-auto bg-[var(--color-bg)]">
      <div className="border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6 pt-5">
        <div className="mx-auto max-w-7xl">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[var(--color-accent-subtle)]">
              {tabIconNode(activeTab)}
            </div>
            <div className="min-w-0">
              <h1 className="text-lg font-semibold tracking-tight text-[var(--color-text-primary)]">
                Sources
              </h1>
              <p className="text-xs text-[var(--color-text-secondary)] truncate">{activeMeta.description}</p>
            </div>
            {showAddButton && (
              <button
                type="button"
                onClick={() => setShowAdd(true)}
                className="ml-auto shrink-0 rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-accent-on)] transition-colors hover:bg-[var(--color-accent-hover)] focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] focus-visible:outline-none"
              >
                Add Connection
              </button>
            )}
          </div>

          <div role="tablist" aria-label="Source categories" className="mt-4 flex gap-1">
            {TABS.map((tab) => {
              const active = tab.id === activeTab
              return (
                <button
                  key={tab.id}
                  role="tab"
                  type="button"
                  aria-selected={active}
                  onClick={() => handleTabChange(tab.id)}
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
      </div>

      {/* Active tab content */}
      {activeTab === "repositories" ? (
        <RepositoriesPanel />
      ) : (
        <SourcePageShell
          key={activeTab}
          category={activeTab as SourceCategory}
          canEdit={canEdit}
          icon={tabIconNode(activeTab)}
          showHeader={false}
          controlledShowAdd={showAdd}
          onControlledShowAddChange={setShowAdd}
        />
      )}
    </div>
  )
}
