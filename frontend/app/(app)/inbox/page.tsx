"use client"

import { Suspense } from "react"
import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import { InboxIcon } from "@/lib/shared/ui/page-icons"
import { InboxQueueSidebar } from "./InboxQueueSidebar"

export default function InboxPage() {
  return (
    <FindingsBoardView
      pageTitle="Inbox"
      pageIcon={<InboxIcon />}
      pageDescription="Triage open findings from your scanners — newest first, grouped by queue."
      initialStateFilter={["open"]}
      showSummaryStrip={false}
      compactHeader
      leftSidebar={(api) => (
        <Suspense fallback={null}>
          <InboxQueueSidebar
            applyView={api.applyView}
            currentUrlState={api.currentUrlState}
            savedViewsRefreshSignal={api.savedViewsRefreshSignal}
            onSavedViewCreated={api.onSavedViewCreated}
          />
        </Suspense>
      )}
    />
  )
}
