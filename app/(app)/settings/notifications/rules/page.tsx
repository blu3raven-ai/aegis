"use client"

import { RoutingRulesPanel } from "@/components/shared/notifications/RoutingRulesPanel"

const ORG_ID = process.env.NEXT_PUBLIC_ORG_ID ?? "example-org"

export default function NotificationRoutingRulesPage() {
  return (
    <div className="mx-auto max-w-5xl p-6 lg:p-10">
      <RoutingRulesPanel orgId={ORG_ID} />
    </div>
  )
}
