"use client"

import { Suspense } from "react"
import { FindingsBoardView } from "@/components/shared/findings/FindingsBoardView"
import { InboxIcon } from "@/lib/shared/ui/page-icons"
import { InboxQueueSidebar } from "../InboxQueueSidebar"

// Triage tab — the open-findings work queue. The shared "Inbox" header and
// the Triage/History tab bar live in the inbox layout.
export default function InboxTriagePage() {
  return (
    <FindingsBoardView
      hideHeader
      pageTitle="Inbox"
      pageIcon={<InboxIcon />}
      pageDescription="Triage open findings, newest first."
      initialStateFilter={["open"]}
      showSummaryStrip={false}
      compactHeader
      flat
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
