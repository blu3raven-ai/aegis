"use client"

import { useCallback } from "react"
import { useRouter } from "next/navigation"
import { useMountedPathname } from "@/lib/client/use-mounted-pathname"
import { PageHeader } from "@/components/layout/PageHeader"
import { NavTabs } from "@/components/ui/NavTabs"
import { InboxIcon } from "@/lib/shared/ui/page-icons"

type InboxTab = "triage" | "history"

const TABS = [
  { id: "triage" as const, label: "Triage" },
  { id: "history" as const, label: "History" },
]

const TAB_HREF: Record<InboxTab, string> = {
  triage: "/inbox/triage",
  history: "/inbox/history",
}

export default function InboxLayout({ children }: { children: React.ReactNode }) {
  const pathname = useMountedPathname()
  const router = useRouter()
  const active: InboxTab = pathname?.startsWith("/inbox/history") ? "history" : "triage"

  const handleChange = useCallback(
    (next: InboxTab) => {
      router.push(TAB_HREF[next])
    },
    [router],
  )

  return (
    <div className="flex h-full flex-col overflow-hidden bg-[var(--color-bg)]">
      <PageHeader
        icon={<InboxIcon />}
        title="Inbox"
        description="Triage open findings and review recent history."
      />
      <NavTabs<InboxTab>
        tabs={TABS}
        activeTab={active}
        onChange={handleChange}
        ariaLabel="Inbox views"
      />
      <div className="flex-1 min-h-0 overflow-hidden">{children}</div>
    </div>
  )
}
