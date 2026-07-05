"use client"

import { useRouter } from "next/navigation"

import { useMountedPathname } from "@/lib/client/use-mounted-pathname"
import { PageHeader } from "@/components/layout/PageHeader"
import { Button } from "@/components/ui/Button"
import { NavTabs } from "@/components/ui/NavTabs"
import { NotificationsIcon } from "@/lib/shared/ui/page-icons"

const TABS = [
  { id: "channels", label: "Channels" },
  { id: "routing", label: "Routing" },
] as const

type TabId = (typeof TABS)[number]["id"]

const PLUS_ICON = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <line x1="12" y1="5" x2="12" y2="19" />
    <line x1="5" y1="12" x2="19" y2="12" />
  </svg>
)

export default function NotificationsLayout({ children }: { children: React.ReactNode }) {
  const pathname = useMountedPathname()
  const router = useRouter()

  const segments = (pathname ?? "").split("/")
  const activeTab = (segments[2] as TabId) || "channels"

  return (
    <>
      <PageHeader
        icon={<NotificationsIcon />}
        title="Notifications"
        description="Channels and routing rules"
        controls={
          <Button
            variant="primary"
            size="sm"
            onClick={() => router.push("/integrations?category=notifications")}
            leadingIcon={PLUS_ICON}
          >
            Add channel
          </Button>
        }
      />

      <NavTabs
        tabs={TABS}
        activeTab={activeTab}
        onChange={(next) => router.push(`/notifications/${next}`)}
        ariaLabel="Notifications sub-navigation"
        containerClassName="sticky top-[var(--page-header-offset)] z-10"
      />

      {children}
    </>
  )
}
