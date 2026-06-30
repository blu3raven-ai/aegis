"use client"

import { useRouter } from "next/navigation"

import { useMountedPathname } from "@/lib/client/use-mounted-pathname"
import { PageHeader } from "@/components/layout/PageHeader"
import { NavTabs } from "@/components/ui/NavTabs"
import { SbomIcon } from "@/lib/shared/ui/page-icons"

const TABS = [
  { id: "repositories", label: "Repositories" },
  { id: "components", label: "Components" },
  { id: "risk", label: "Risky Packages" },
  { id: "compare", label: "Compare" },
] as const

type TabId = (typeof TABS)[number]["id"]

const TAB_ROUTE: Record<TabId, string> = {
  repositories: "/sbom",
  components: "/sbom/components",
  risk: "/sbom/risk",
  compare: "/sbom/diff",
}

/**
 * Section chrome for the SBOM home (Repositories / Components / Risky Packages /
 * Compare). The per-repo detail at /sbom/[repoId] sits outside this route group
 * on purpose — it's a drill-down with its own header, not a tab.
 */
export default function SbomHomeLayout({ children }: { children: React.ReactNode }) {
  const pathname = useMountedPathname()
  const router = useRouter()

  const sub = (pathname ?? "").split("/")[2]
  const activeTab: TabId =
    sub === "components"
      ? "components"
      : sub === "risk"
        ? "risk"
        : sub === "diff"
          ? "compare"
          : "repositories"

  return (
    <>
      <PageHeader
        icon={<SbomIcon />}
        title="SBOM"
        description="Software bills of materials across your repositories."
      />
      <NavTabs
        tabs={TABS}
        activeTab={activeTab}
        onChange={(t) => router.push(TAB_ROUTE[t])}
        ariaLabel="SBOM views"
        containerClassName="sticky top-[var(--page-header-offset)] z-10"
      />
      {children}
    </>
  )
}
